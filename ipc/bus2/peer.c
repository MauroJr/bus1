/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/pid_namespace.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/linux/bus1.h>
#include "main.h"
#include "peer.h"
#include "user.h"
#include "util/active.h"
#include "util/pool.h"
#include "util/queue.h"

/**
 * bus1_peer_new() - allocate new peer
 *
 * Allocate a new peer. It is immediately activated and ready for use. It is
 * not linked into any context. The caller will get exclusively access to the
 * peer object on success.
 *
 * Note that the peer is opened on behalf of 'current'. That is, it pins its
 * credentials and namespaces.
 *
 * Return: Pointer to peer, ERR_PTR on failure.
 */
struct bus1_peer *bus1_peer_new(void)
{
	static atomic64_t peer_ids = ATOMIC64_INIT(0);
	const struct cred *cred = current_cred();
	struct bus1_peer *peer;
	struct bus1_user *user;
	int r;

	user = bus1_user_ref_by_uid(cred->uid);
	if (IS_ERR(user))
		return ERR_CAST(user);

	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer) {
		bus1_user_unref(user);
		return ERR_PTR(-ENOMEM);
	}

	/* initialize constant fields */
	peer->id = 0;
	peer->flags = 0;
	peer->cred = get_cred(current_cred());
	peer->pid_ns = get_pid_ns(task_active_pid_ns(current));
	peer->user = user;
	bus1_user_limits_init(&peer->limits, peer->user);
	peer->debugdir = NULL;
	init_waitqueue_head(&peer->waitq);
	bus1_active_init(&peer->active);

	/* initialize data section */
	mutex_init(&peer->data.lock);
	peer->data.pool = BUS1_POOL_NULL;
	bus1_queue_init(&peer->data.queue);

	/* initialize peer-private section */
	mutex_init(&peer->local.lock);
	peer->local.seed = NULL;
	peer->local.map_handles = RB_ROOT;
	peer->local.handle_ids = 0;

	r = bus1_pool_init(&peer->data.pool, KBUILD_MODNAME "-peer");
	if (r < 0)
		goto error;

	peer->id = atomic64_inc_return(&peer_ids);

	if (!IS_ERR_OR_NULL(bus1_debugdir)) {
		char idstr[22];

		snprintf(idstr, sizeof(idstr), "peer-%llx", peer->id);

		peer->debugdir = debugfs_create_dir(idstr, bus1_debugdir);
		if (!peer->debugdir) {
			pr_err("cannot create debugfs dir for peer %llx\n",
			       peer->id);
		} else if (!IS_ERR_OR_NULL(peer->debugdir)) {
			bus1_debugfs_create_atomic_x("active", S_IRUGO,
						     peer->debugdir,
						     &peer->active.count);
		}
	}

	bus1_active_activate(&peer->active);
	return peer;

error:
	bus1_peer_free(peer);
	return ERR_PTR(r);
}

static void bus1_peer_reset(struct bus1_peer *peer, u64 flags)
{
	size_t n_slices;

	lockdep_assert_held(&peer->local.lock);
	lockdep_assert_held(&peer->data.lock);

	if (flags & BUS1_PEER_RESET_FLAG_FLUSH_SEED)
		/* XXX */ ;

	if (flags & BUS1_PEER_RESET_FLAG_FLUSH) {
		bus1_pool_flush(&peer->data.pool, &n_slices);
		bus1_user_charge(&peer->user->limits.n_slices,
				 &peer->limits.n_slices, -n_slices);
	}
}

static void bus1_peer_cleanup(struct bus1_active *a, void *userdata)
{
	struct bus1_peer *peer = container_of(a, struct bus1_peer, active);

	mutex_lock(&peer->local.lock);
	mutex_lock(&peer->data.lock);

	bus1_peer_reset(peer, BUS1_PEER_RESET_FLAG_FLUSH |
			      BUS1_PEER_RESET_FLAG_FLUSH_SEED);

	mutex_unlock(&peer->data.lock);
	mutex_unlock(&peer->local.lock);
}

static int bus1_peer_disconnect(struct bus1_peer *peer)
{
	bus1_active_deactivate(&peer->active);
	bus1_active_drain(&peer->active, &peer->waitq);

	if (!bus1_active_cleanup(&peer->active, &peer->waitq,
				 bus1_peer_cleanup, NULL))
		return -ESHUTDOWN;

	return 0;
}

/**
 * bus1_peer_free() - destroy peer
 * @peer:	peer to destroy, or NULL
 *
 * Destroy a peer object that was previously allocated via bus1_peer_new().
 * This synchronously waits for any outstanding operations on this peer to
 * finish, then releases all linked resources and deallocates the peer in an
 * rcu-delayed manner.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_peer *bus1_peer_free(struct bus1_peer *peer)
{
	if (!peer)
		return NULL;

	/* disconnect from environment */
	bus1_peer_disconnect(peer);

	/* deinitialize peer-private section */
	WARN_ON(!RB_EMPTY_ROOT(&peer->local.map_handles));
	WARN_ON(peer->local.seed);
	mutex_destroy(&peer->local.lock);

	/* deinitialize data section */
	bus1_queue_deinit(&peer->data.queue);
	bus1_pool_deinit(&peer->data.pool);
	mutex_destroy(&peer->data.lock);

	/* deinitialize constant fields */
	debugfs_remove_recursive(peer->debugdir);
	bus1_active_deinit(&peer->active);
	bus1_user_limits_deinit(&peer->limits);
	peer->user = bus1_user_unref(peer->user);
	put_pid_ns(peer->pid_ns);
	put_cred(peer->cred);
	kfree_rcu(peer, local.rcu);

	return NULL;
}

static int bus1_peer_ioctl_peer_query(struct bus1_peer *peer,
				      unsigned long arg)
{
	struct bus1_cmd_peer_reset __user *uparam = (void __user *)arg;
	struct bus1_cmd_peer_reset param;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_QUERY) != sizeof(param));

	if (copy_from_user(&param, uparam, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags))
		return -EINVAL;

	mutex_lock(&peer->local.lock);
	param.peer_flags = peer->flags & BUS1_PEER_FLAG_WANT_SECCTX;
	param.max_slices = peer->limits.max_slices;
	param.max_handles = peer->limits.max_handles;
	param.max_inflight_bytes = peer->limits.max_inflight_bytes;
	param.max_inflight_fds = peer->limits.max_inflight_fds;
	mutex_unlock(&peer->local.lock);

	return copy_to_user(uparam, &param, sizeof(param)) ? -EFAULT : 0;
}

static int bus1_peer_ioctl_peer_reset(struct bus1_peer *peer,
				      unsigned long arg)
{
	struct bus1_cmd_peer_reset __user *uparam = (void __user *)arg;
	struct bus1_cmd_peer_reset param;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_PEER_RESET) != sizeof(param));

	if (copy_from_user(&param, uparam, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~(BUS1_PEER_RESET_FLAG_FLUSH |
				     BUS1_PEER_RESET_FLAG_FLUSH_SEED)))
		return -EINVAL;
	if (unlikely(param.peer_flags != -1 &&
		     (param.peer_flags & ~BUS1_PEER_FLAG_WANT_SECCTX)))
		return -EINVAL;
	if (unlikely((param.max_slices != -1 &&
		      param.max_slices > INT_MAX) ||
		     (param.max_handles != -1 &&
		      param.max_handles > INT_MAX) ||
		     (param.max_inflight_bytes != -1 &&
		      param.max_inflight_bytes > INT_MAX) ||
		     (param.max_inflight_fds != -1 &&
		      param.max_inflight_fds > INT_MAX)))
		return -EINVAL;

	mutex_lock(&peer->local.lock);

	if (param.peer_flags != -1)
		peer->flags = param.peer_flags;

	if (param.max_slices != -1) {
		atomic_add((int)param.max_slices -
			   (int)peer->limits.max_slices,
			   &peer->limits.n_slices);
		peer->limits.max_slices = param.max_slices;
	}

	if (param.max_handles != -1) {
		atomic_add((int)param.max_handles -
			   (int)peer->limits.max_handles,
			   &peer->limits.n_handles);
		peer->limits.max_handles = param.max_handles;
	}

	if (param.max_inflight_bytes != -1) {
		atomic_add((int)param.max_inflight_bytes -
			   (int)peer->limits.max_inflight_bytes,
			   &peer->limits.n_inflight_bytes);
		peer->limits.max_inflight_bytes = param.max_inflight_bytes;
	}

	if (param.max_inflight_fds != -1) {
		atomic_add((int)param.max_inflight_fds -
			   (int)peer->limits.max_inflight_fds,
			   &peer->limits.n_inflight_fds);
		peer->limits.max_inflight_fds = param.max_inflight_fds;
	}

	mutex_lock(&peer->data.lock);
	bus1_peer_reset(peer, param.flags);
	mutex_unlock(&peer->data.lock);

	mutex_unlock(&peer->local.lock);

	return 0;
}

static int bus1_peer_ioctl_slice_release(struct bus1_peer *peer,
					 unsigned long arg)
{
	size_t n_slices = 0;
	u64 offset;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_SLICE_RELEASE) != sizeof(offset));

	if (get_user(offset, (const u64 __user *)arg))
		return -EFAULT;

	mutex_lock(&peer->data.lock);
	r = bus1_pool_release_user(&peer->data.pool, offset, &n_slices);
	mutex_unlock(&peer->data.lock);
	bus1_user_charge(&peer->user->limits.n_slices,
			 &peer->limits.n_slices, -n_slices);
	return r;
}

/**
 * bus1_peer_ioctl() - handle peer ioctls
 * @file:		file the ioctl is called on
 * @cmd:		ioctl command
 * @arg:		ioctl argument
 *
 * This handles the given ioctl (cmd+arg) on a peer. This expects the peer to
 * be stored in the private_data field of @file.
 *
 * Multiple ioctls can be called in parallel just fine. No locking is needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
long bus1_peer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct bus1_peer *peer = file->private_data;
	int r;

	/*
	 * First handle ioctls that do not require an active-reference, then
	 * all the remaining ones wrapped in an active reference.
	 */
	switch (cmd) {
	case BUS1_CMD_PEER_DISCONNECT:
		if (unlikely(arg))
			return -EINVAL;

		r = bus1_peer_disconnect(peer);
		break;
	default:
		if (!bus1_peer_acquire(peer))
			return -ESHUTDOWN;

		switch (cmd) {
		case BUS1_CMD_PEER_QUERY:
			r = bus1_peer_ioctl_peer_query(peer, arg);
			break;
		case BUS1_CMD_PEER_RESET:
			r = bus1_peer_ioctl_peer_reset(peer, arg);
			break;
		case BUS1_CMD_HANDLE_RELEASE:
			r = -ENOTRECOVERABLE;
			break;
		case BUS1_CMD_HANDLE_TRANSFER:
			r = -ENOTRECOVERABLE;
			break;
		case BUS1_CMD_NODES_DESTROY:
			r = -ENOTRECOVERABLE;
			break;
		case BUS1_CMD_SLICE_RELEASE:
			r = bus1_peer_ioctl_slice_release(peer, arg);
			break;
		case BUS1_CMD_SEND:
			r = -ENOTRECOVERABLE;
			break;
		case BUS1_CMD_RECV:
			r = -ENOTRECOVERABLE;
			break;
		default:
			r = -ENOTTY;
			break;
		}

		bus1_peer_release(peer);
		break;
	}

	return r;
}
