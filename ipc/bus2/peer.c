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
#include "message.h"
#include "node.h"
#include "peer.h"
#include "tx.h"
#include "user.h"
#include "util.h"
#include "util/active.h"
#include "util/pool.h"
#include "util/queue.h"

static struct bus1_queue_node *
bus1_peer_free_qnode(struct bus1_queue_node *qnode)
{
	struct bus1_message *m;
	struct bus1_handle *h;

	/*
	 * Queue-nodes are generic entities that can only be destroyed by who
	 * created them. That is, they have no embedded release callback.
	 * Instead, we must detect them by type. Since the queue logic is kept
	 * generic, it cannot provide this helper. Instead, we have this small
	 * destructor here, which simply dispatches to the correct handler.
	 */

	if (qnode) {
		switch (bus1_queue_node_get_type(qnode)) {
		case BUS1_MSG_DATA:
			m = container_of(qnode, struct bus1_message, qnode);
			bus1_message_unref(m);
			break;
		case BUS1_MSG_NODE_DESTROY:
		case BUS1_MSG_NODE_RELEASE:
			h = container_of(qnode, struct bus1_handle, qnode);
			bus1_handle_unref(h);
			break;
		case BUS1_MSG_NONE:
		default:
			WARN(1, "Unknown message type");
			break;
		}
	}

	return NULL;
}

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
	peer->id = atomic64_inc_return(&peer_ids);
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

static void bus1_peer_flush(struct bus1_peer *peer, u64 flags)
{
	struct bus1_queue_node *qlist, *qnode;
	struct bus1_handle *h, *safe;
	struct bus1_tx tx;
	size_t n_slices;
	u64 ts;
	int n;

	lockdep_assert_held(&peer->local.lock);

	bus1_tx_init(&tx, peer);

	if (flags & BUS1_PEER_RESET_FLAG_FLUSH) {
		/* protect handles on the seed */
		if (!(flags & BUS1_PEER_RESET_FLAG_FLUSH_SEED) &&
		    peer->local.seed) {
			/* XXX */
		}

		/* first destroy all live anchors */
		mutex_lock(&peer->data.lock);
		rbtree_postorder_for_each_entry_safe(h, safe,
						     &peer->local.map_handles,
						     rb_to_peer) {
			if (!bus1_handle_is_anchor(h) ||
			    !bus1_handle_is_live(h))
				continue;

			bus1_handle_destroy_locked(h, &tx);
		}
		mutex_unlock(&peer->data.lock);

		/* atomically commit the destruction transaction */
		ts = bus1_tx_commit(&tx);

		/* now release all user handles */
		rbtree_postorder_for_each_entry_safe(h, safe,
						     &peer->local.map_handles,
						     rb_to_peer) {
			n = atomic_xchg(&h->n_user, 0);
			bus1_handle_forget_keep(peer, h);
			bus1_user_charge(&peer->user->limits.n_handles,
					 &peer->limits.n_handles, -n);

			if (bus1_handle_is_anchor(h)) {
				if (n > 1)
					bus1_handle_release_n(h, n - 1, true);
				bus1_handle_release(h, false);
			} else {
				bus1_handle_release_n(h, n, true);
			}
		}
		peer->local.map_handles = RB_ROOT;

		/* finally flush the queue and pool */
		mutex_lock(&peer->data.lock);
		qlist = bus1_queue_flush(&peer->data.queue, ts);
		bus1_pool_flush(&peer->data.pool, &n_slices);
		mutex_unlock(&peer->data.lock);

		bus1_user_charge(&peer->user->limits.n_slices,
				 &peer->limits.n_slices, -n_slices);

		while ((qnode = qlist)) {
			qlist = qnode->next;
			qnode->next = NULL;
			bus1_peer_free_qnode(qnode);
		}
	}

	/* drop seed if requested */
	if (flags & BUS1_PEER_RESET_FLAG_FLUSH_SEED)
		peer->local.seed = bus1_message_unref(peer->local.seed);

	bus1_tx_deinit(&tx);
}

static void bus1_peer_cleanup(struct bus1_active *a, void *userdata)
{
	struct bus1_peer *peer = container_of(a, struct bus1_peer, active);

	mutex_lock(&peer->local.lock);
	bus1_peer_flush(peer, BUS1_PEER_RESET_FLAG_FLUSH |
			      BUS1_PEER_RESET_FLAG_FLUSH_SEED);
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
	kfree_rcu(peer, rcu);

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

	bus1_peer_flush(peer, param.flags);

	mutex_unlock(&peer->local.lock);

	return 0;
}

static int bus1_peer_ioctl_handle_release(struct bus1_peer *peer,
					  unsigned long arg)
{
	struct bus1_handle *h = NULL;
	bool strong = true;
	u64 id;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_HANDLE_RELEASE) != sizeof(id));

	if (get_user(id, (const u64 __user *)arg))
		return -EFAULT;

	mutex_lock(&peer->local.lock);

	h = bus1_handle_import(peer, id);
	if (IS_ERR(h)) {
		r = PTR_ERR(h);
		goto exit;
	}

	if (!bus1_handle_is_public(h)) {
		/*
		 * A handle is non-public only if the import lazily created the
		 * node. In that case the node is live and the last reference
		 * cannot be dropped until the node is destroyed. Hence, we
		 * return EBUSY.
		 *
		 * Since we did not modify the node, and the node was lazily
		 * created, there is no point in keeping the node allocated. We
		 * simply pretend we didn't allocate it so the next operation
		 * will just do the lazy allocation again.
		 */
		bus1_handle_forget(peer, h);
		r = -EBUSY;
		goto exit;
	}

	if (atomic_read(&h->n_user) == 1 && bus1_handle_is_anchor(h)) {
		if (bus1_handle_is_live(h))
			return -EBUSY;

		strong = false;
	}

	WARN_ON(atomic_dec_return(&h->n_user) < 0);
	bus1_handle_forget(peer, h);
	bus1_user_charge(&peer->user->limits.n_handles,
			 &peer->limits.n_handles, -1);
	bus1_handle_release(h, strong);

	r = 0;

exit:
	mutex_unlock(&peer->local.lock);
	bus1_handle_unref(h);
	return r;
}

static int bus1_peer_transfer(struct bus1_peer *src,
			      struct bus1_peer *dst,
			      struct bus1_cmd_handle_transfer *param)
{
	struct bus1_handle *src_h = NULL, *dst_h = NULL;
	int r;

	bus1_mutex_lock2(&src->local.lock, &dst->local.lock);

	src_h = bus1_handle_import(src, param->src_handle);
	if (IS_ERR(src_h)) {
		r = PTR_ERR(src_h);
		src_h = NULL;
		goto exit;
	}

	dst_h = bus1_handle_ref_by_other(dst, src_h);
	if (!dst_h) {
		dst_h = bus1_handle_new_remote(src_h);
		if (IS_ERR(dst_h)) {
			r = PTR_ERR(dst_h);
			dst_h = NULL;
			goto exit;
		}
	}

	if (!bus1_user_charge(&dst->user->limits.n_handles,
			      &dst->limits.n_handles, 1)) {
		r = -EDQUOT;
		goto exit;
	}

	if (!bus1_handle_is_public(src_h)) {
		if (!bus1_user_charge(&src->user->limits.n_handles,
				      &src->limits.n_handles, 1)) {
			bus1_user_charge(&dst->user->limits.n_handles,
					 &dst->limits.n_handles, -1);
			r = -EDQUOT;
			goto exit;
		}

		WARN_ON(src_h != bus1_handle_acquire(src_h, src, false));
		WARN_ON(atomic_inc_return(&src_h->n_user) != 1);
	}

	dst_h = bus1_handle_acquire(dst_h, dst, true);
	if (bus1_handle_export(dst_h, 0)) {
		atomic_inc(&dst_h->n_user);
		param->dst_handle = dst_h->id;
	} else {
		bus1_user_charge(&dst->user->limits.n_handles,
				 &dst->limits.n_handles, -1);
		bus1_handle_release(dst_h, true);
		param->dst_handle = BUS1_HANDLE_INVALID;
	}

	r = 0;

exit:
	bus1_handle_forget(src, src_h);
	bus1_mutex_unlock2(&src->local.lock, &dst->local.lock);
	/* XXX: bus1_handle_settle(src_h); */
	bus1_handle_unref(dst_h);
	bus1_handle_unref(src_h);
	return r;
}

static int bus1_peer_ioctl_handle_transfer(struct bus1_peer *src,
					   unsigned long arg)
{
	struct bus1_cmd_handle_transfer __user *uparam = (void __user *)arg;
	struct bus1_cmd_handle_transfer param;
	struct bus1_peer *dst = NULL;
	struct fd dst_f;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_HANDLE_TRANSFER) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags))
		return -EINVAL;

	if (param.dst_fd != -1) {
		dst_f = fdget(param.dst_fd);
		if (!dst_f.file)
			return -EBADF;
		if (dst_f.file->f_op != &bus1_fops) {
			fdput(dst_f);
			return -EOPNOTSUPP;
		}

		dst = bus1_peer_acquire(dst_f.file->private_data);
		fdput(dst_f);
		if (!dst)
			return -ESHUTDOWN;
	}

	r = bus1_peer_transfer(src, dst ?: src, &param);
	bus1_peer_release(dst);
	if (r < 0)
		return r;

	return copy_to_user(uparam, &param, sizeof(param)) ? -EFAULT : 0;
}

static int bus1_peer_ioctl_nodes_destroy(struct bus1_peer *peer,
					 unsigned long arg)
{
	struct bus1_cmd_nodes_destroy param;
	size_t n_charge = 0, n_discharge = 0;
	struct bus1_handle *h, *list = BUS1_TAIL;
	const u64 __user *ptr_nodes;
	u64 i, id;
	int r;

	BUILD_BUG_ON(_IOC_SIZE(BUS1_CMD_NODES_DESTROY) != sizeof(param));

	if (copy_from_user(&param, (void __user *)arg, sizeof(param)))
		return -EFAULT;
	if (unlikely(param.flags & ~BUS1_NODES_DESTROY_FLAG_RELEASE_HANDLES))
		return -EINVAL;
	if (unlikely(param.ptr_nodes != (u64)(unsigned long)param.ptr_nodes))
		return -EFAULT;

	ptr_nodes = (const u64 __user *)(unsigned long)param.ptr_nodes;

	mutex_lock(&peer->local.lock);

	/*
	 * We must limit the work that user-space can dispatch in one go. We
	 * use the maximum number of handles as natural limit. You cannot hit
	 * it, anyway, except if your call would fail without it as well.
	 */
	if (unlikely(param.n_nodes > peer->user->limits.max_handles)) {
		r = -EINVAL;
		goto exit;
	}

	for (i = 0; i < param.n_nodes; ++i) {
		if (get_user(id, ptr_nodes + i)) {
			r = -EFAULT;
			goto exit;
		}

		h = bus1_handle_import(peer, id);
		if (IS_ERR(h)) {
			r = PTR_ERR(h);
			goto exit;
		}

		if (h->tlink) {
			bus1_handle_unref(h);
			r = -ENOTUNIQ;
			goto exit;
		}

		h->tlink = list;
		list = h;

		if (!bus1_handle_is_anchor(h)) {
			r = -EREMOTE;
			goto exit;
		}

		if (!bus1_handle_is_live(h)) {
			r = -ESTALE;
			goto exit;
		}

		if (!bus1_handle_is_public(h))
			++n_charge;
	}

	if (!bus1_user_charge(&peer->user->limits.n_handles,
			      &peer->limits.n_handles, n_charge)) {
		r = -EDQUOT;
		goto exit;
	}

	/* nothing below this point can fail, anymore */

	mutex_lock(&peer->data.lock);
	for (h = list; h != BUS1_TAIL; h = h->tlink) {
		if (!bus1_handle_is_public(h)) {
			WARN_ON(h != bus1_handle_acquire_locked(h, peer,
								false));
			WARN_ON(atomic_inc_return(&h->n_user) != 1);
		}

		bus1_handle_destroy_locked(h, NULL);
	}
	mutex_unlock(&peer->data.lock);

	while (list != BUS1_TAIL) {
		h = list;
		list = h->tlink;
		h->tlink = NULL;

		if (param.flags & BUS1_NODES_DESTROY_FLAG_RELEASE_HANDLES) {
			++n_discharge;
			if (atomic_dec_return(&h->n_user) == 0) {
				bus1_handle_forget(peer, h);
				bus1_handle_release(h, false);
			} else {
				bus1_handle_release(h, true);
			}
		}

		bus1_handle_unref(h);
	}

	bus1_user_charge(&peer->user->limits.n_handles,
			 &peer->limits.n_handles, -n_discharge);

	r = 0;

exit:
	while ((h = list)) {
		list = h->tlink;
		h->tlink = NULL;

		bus1_handle_forget(peer, h);
		bus1_handle_unref(h);
	}
	mutex_unlock(&peer->local.lock);
	return r;
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
			r = bus1_peer_ioctl_handle_release(peer, arg);
			break;
		case BUS1_CMD_HANDLE_TRANSFER:
			r = bus1_peer_ioctl_handle_transfer(peer, arg);
			break;
		case BUS1_CMD_NODES_DESTROY:
			r = bus1_peer_ioctl_nodes_destroy(peer, arg);
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