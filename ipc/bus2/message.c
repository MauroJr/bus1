/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/uio.h>
#include <uapi/linux/bus1.h>
#include "message.h"
#include "node.h"
#include "peer.h"
#include "security.h"
#include "user.h"
#include "util.h"
#include "util/flist.h"
#include "util/pool.h"
#include "util/queue.h"

static size_t bus1_factory_size(struct bus1_cmd_send *param)
{
	/* make sure @size cannot overflow */
	BUILD_BUG_ON(UIO_MAXIOV > U16_MAX);
	BUILD_BUG_ON(BUS1_FD_MAX > U16_MAX);

	/* make sure we do not violate alignment rules */
	BUILD_BUG_ON(__alignof(struct bus1_flist) < __alignof(struct iovec));
	BUILD_BUG_ON(__alignof(struct iovec) < __alignof(struct file *));

	return sizeof(struct bus1_factory) +
	       bus1_flist_inline_size(param->n_handles) +
	       param->n_vecs * sizeof(struct iovec) +
	       param->n_fds * sizeof(struct file *);
}

/**
 * bus1_factory_new() - create new message factory
 * @peer:			peer to operate as
 * @param:			factory parameters
 * @stack:			optional stack for factory, or NULL
 * @n_stack:			size of space at @stack
 *
 * This allocates a new message factory. It imports data from @param and
 * prepares the factory for a transaction. From this factory, messages can be
 * instantiated. This is used both for unicasts and multicasts.
 *
 * If @stack is given, this tries to place the factory on the specified stack
 * space. The caller must guarantee that the factory does not outlive the stack
 * frame. If this is not wanted, pass 0 as @n_stack.
 * In either case, if the stack frame is too small, this will allocate the
 * factory on the heap.
 *
 * Return: Pointer to factory, or ERR_PTR on failure.
 */
struct bus1_factory *bus1_factory_new(struct bus1_peer *peer,
				      struct bus1_cmd_send *param,
				      void *stack,
				      size_t n_stack)
{
	const struct iovec __user *ptr_vecs;
	const int __user *ptr_fds;
	struct bus1_factory *f;
	struct file *file;
	size_t size;
	int r, fd;
	u32 sid;

	size = bus1_factory_size(param);
	if (unlikely(size > n_stack)) {
		f = kmalloc(size, GFP_TEMPORARY);
		if (!f)
			return ERR_PTR(-ENOMEM);

		f->on_stack = false;
	} else {
		f = stack;
		f->on_stack = true;
	}

	/* set to default first, so the destructor can be called anytime */
	f->peer = peer;
	f->param = param;
	f->cred = current_cred();
	f->pid = task_tgid(current);
	f->tid = task_pid(current);

	f->has_secctx = false;

	f->length_vecs = 0;
	f->n_vecs = param->n_vecs;
	f->n_handles = 0;
	f->n_files = 0;
	f->n_secctx = 0;
	f->vecs = (void *)(f + 1) + bus1_flist_inline_size(param->n_handles);
	f->files = (void *)(f->vecs + param->n_vecs);
	f->secctx = NULL;
	bus1_flist_init(f->handles, f->param->n_handles);

	/* import vecs */
	ptr_vecs = (const struct iovec __user *)(unsigned long)param->ptr_vecs;
	r = bus1_import_vecs(f->vecs, &f->length_vecs, ptr_vecs, f->n_vecs);
	if (r < 0)
		goto error;

	/* import handles */
	r = bus1_flist_populate(f->handles, f->param->n_handles, GFP_TEMPORARY);
	if (r < 0)
		goto error;

	/* XXX: import handles */

	/* import files */
	ptr_fds = (const int __user *)(unsigned long)param->ptr_fds;
	while (f->n_files < param->n_fds) {
		if (unlikely(get_user(fd, ptr_fds + f->n_files))) {
			r = -EFAULT;
			goto error;
		}

		file = bus1_import_fd(fd);
		if (IS_ERR(file)) {
			r = PTR_ERR(file);
			goto error;
		}

		f->files[f->n_files++] = file;
	}

	/* import secctx */
	security_task_getsecid(current, &sid);
	r = security_secid_to_secctx(sid, &f->secctx, &f->n_secctx);
	if (r != -EOPNOTSUPP) {
		if (r < 0)
			goto error;

		f->has_secctx = true;
	}

	return f;

error:
	bus1_factory_free(f);
	return ERR_PTR(r);
}

/**
 * bus1_factory_free() - destroy message factory
 * @f:				factory to operate on, or NULL
 *
 * This destroys the message factory @f, previously created via
 * bus1_factory_new(). All pinned resources are freed. Messages created via the
 * factory are unaffected.
 *
 * If @f is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_factory *bus1_factory_free(struct bus1_factory *f)
{
	size_t i;

	if (f) {
		if (f->has_secctx)
			security_release_secctx(f->secctx, f->n_secctx);

		for (i = 0; i < f->n_files; ++i)
			fput(f->files[i]);

		bus1_flist_deinit(f->handles, f->param->n_handles);

		if (f->on_stack)
			kfree(f);
	}
	return NULL;
}

/**
 * bus1_factory_instantiate() - instantiate a message from a factory
 * @f:				factory to use
 * @handle:			destination handle
 *
 * This instantiates a new message targetted at @handle, based on the plans in
 * the message factory @f.
 *
 * The newly created message is not linked into any contexts, but is available
 * for free use to the caller.
 *
 * Return: Pointer to new message, or ERR_PTR on failure.
 */
struct bus1_message *bus1_factory_instantiate(struct bus1_factory *f,
					      struct bus1_handle *handle)
{
	struct bus1_flist *src_e, *dst_e;
	struct bus1_message *m;
	struct bus1_peer *peer;
	bool transmit_secctx;
	struct kvec vec;
	size_t size, i, j;
	u64 offset;
	int r;

	peer = bus1_handle_acquire_owner(handle);
	if (!peer)
		return ERR_PTR(-ESHUTDOWN); /* XXX: handle gracefully */

	/* XXX: properly protect @peer->flags */
	transmit_secctx = f->has_secctx &&
			  (READ_ONCE(peer->flags) & BUS1_PEER_FLAG_WANT_SECCTX);

	size = sizeof(*m) + bus1_flist_inline_size(f->n_handles) +
	       f->n_files * sizeof(struct file *);

	m = kmalloc(size, GFP_KERNEL);
	if (!m) {
		bus1_peer_release(peer);
		return ERR_PTR(-ENOMEM);
	}

	/* set to default first, so the destructor can be called anytime */
	kref_init(&m->ref);
	bus1_queue_node_init(&m->qnode, BUS1_MSG_DATA);
	m->qnode.owner = peer;
	m->dst = bus1_handle_ref(handle);
	m->user = bus1_user_ref(f->peer->user);

	m->flags = 0;
	m->uid = from_kuid_munged(peer->cred->user_ns, f->cred->uid);
	m->gid = from_kgid_munged(peer->cred->user_ns, f->cred->gid);
	m->pid = pid_nr_ns(f->pid, peer->pid_ns);
	m->tid = pid_nr_ns(f->tid, peer->pid_ns);

	m->n_bytes = f->length_vecs;
	m->n_handles = 0;
	m->n_files = 0;
	m->n_secctx = 0;
	m->slice = NULL;
	m->files = (void *)(m + 1) + bus1_flist_inline_size(f->n_handles);
	bus1_flist_init(m->handles, f->n_handles);

	/* allocate pool slice */
	size = max_t(size_t, 8,
			     ALIGN(m->n_bytes, 8) +
			     ALIGN(f->n_handles * sizeof(u64), 8) +
			     ALIGN(f->n_files * sizeof(int), 8) +
			     ALIGN(f->n_secctx, 8));
	mutex_lock(&peer->data.lock);
	/* XXX: accounting */
	m->slice = bus1_pool_alloc(&peer->data.pool, size);
	mutex_unlock(&peer->data.lock);
	if (IS_ERR(m->slice)) {
		r = PTR_ERR(m->slice);
		m->slice = NULL;
		goto error;
	}

	/* import blob */
	r = bus1_pool_write_iovec(&peer->data.pool, m->slice, 0, f->vecs,
				  f->n_vecs, f->length_vecs);
	if (r < 0)
		goto error;

	/* import handles */
	r = bus1_flist_populate(m->handles, f->n_handles, GFP_KERNEL);
	if (r < 0)
		goto error;

	r = 0;
	m->n_handles = f->n_handles;
	i = 0;
	j = 0;
	src_e = f->handles;
	dst_e = m->handles;
	while (i < f->n_handles) {
		WARN_ON(i != j);

		dst_e->ptr = bus1_handle_ref_by_other(peer, src_e->ptr);
		if (!dst_e->ptr) {
			dst_e->ptr = bus1_handle_new_remote(src_e->ptr);
			if (IS_ERR(dst_e->ptr) && r >= 0) {
				/*
				 * Continue on error until we imported all
				 * handles. Otherwise, trailing entries in the
				 * array will be stale, and the destructor
				 * cannot tell which.
				 */
				r = PTR_ERR(dst_e->ptr);
			}
		}

		src_e = bus1_flist_next(src_e, &i);
		dst_e = bus1_flist_next(dst_e, &j);
	}
	if (r < 0)
		goto error;

	/* import files */
	while (m->n_files < f->n_files) {
		r = security_bus1_transfer_file(f->peer, peer,
						f->files[m->n_files]);
		if (r < 0)
			goto error;

		m->files[m->n_files] = get_file(f->files[m->n_files]);
		++m->n_files;
	}

	/* import secctx */
	if (transmit_secctx) {
		offset = ALIGN(m->n_bytes, 8) +
			 ALIGN(m->n_handles * sizeof(u64), 8) +
			 ALIGN(m->n_files * sizeof(int), 8);
		vec = (struct kvec){
			.iov_base = f->secctx,
			.iov_len = f->n_secctx,
		};

		r = bus1_pool_write_kvec(&peer->data.pool, m->slice, offset,
					 &vec, 1, vec.iov_len);
		if (r < 0)
			goto error;

		m->n_secctx = f->n_secctx;
		m->flags |= BUS1_MSG_FLAG_HAS_SECCTX;
	}

	return m;

error:
	bus1_message_unref(m);
	return ERR_PTR(r);
}

/**
 * bus1_message_free() - destroy message
 * @k:			kref belonging to a message
 *
 * This frees the message belonging to the reference counter @k. It is supposed
 * to be used with kref_put(). See bus1_message_unref(). Like all queue nodes,
 * the memory deallocation is rcu-delayed.
 */
void bus1_message_free(struct kref *k)
{
	struct bus1_message *m = container_of(k, struct bus1_message, ref);
	struct bus1_peer *peer = m->qnode.owner;
	struct bus1_flist *e;
	size_t i;

	WARN_ON(!peer);

	for (i = 0; i < m->n_files; ++i)
		fput(m->files[i]);

	for (i = 0, e = m->handles;
	     i < m->n_handles;
	     e = bus1_flist_next(e, &i)) {
		if (!IS_ERR(e->ptr))
			bus1_handle_unref(e->ptr);
	}

	bus1_flist_deinit(m->handles, m->n_handles);

	mutex_lock(&peer->data.lock);
	bus1_pool_release_kernel(&peer->data.pool, m->slice);
	mutex_unlock(&peer->data.lock);

	bus1_user_unref(m->user);
	bus1_handle_unref(m->dst);
	bus1_peer_release(peer);
	bus1_queue_node_deinit(&m->qnode);
	kfree_rcu(m, qnode.rcu);
}
