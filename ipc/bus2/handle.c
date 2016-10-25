/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include "handle.h"
#include "peer.h"
#include "tx.h"
#include "util.h"
#include "util/queue.h"

static void bus1_handle_init(struct bus1_handle *h)
{
	kref_init(&h->ref);
	atomic_set(&h->n_weak, 0);
	atomic_set(&h->n_user, 0);
	h->holder = NULL;
	h->anchor = NULL;
	h->tlink = NULL;
	RB_CLEAR_NODE(&h->rb_to_peer);
	h->id = BUS1_HANDLE_INVALID;
}

static void bus1_handle_deinit(struct bus1_handle *h)
{
	if (h == h->anchor) {
		WARN_ON(atomic_read(&h->node.n_strong) != 0);
		WARN_ON(!RB_EMPTY_ROOT(&h->node.map_handles));
	} else if (h->anchor) {
		WARN_ON(!RB_EMPTY_NODE(&h->remote.rb_to_anchor));
		bus1_handle_unref(h->anchor);
	}

	bus1_queue_node_deinit(&h->qnode);
	WARN_ON(!RB_EMPTY_NODE(&h->rb_to_peer));
	WARN_ON(h->tlink);
	WARN_ON(atomic_read(&h->n_user) != 0);
	WARN_ON(atomic_read(&h->n_weak) != 0);
}

/**
 * bus1_handle_new_anchor() - allocate new anchor handle
 *
 * This allocates a new, fresh, anchor handle for free use to the caller.
 *
 * Return: Pointer to handle, or ERR_PTR on failure.
 */
struct bus1_handle *bus1_handle_new_anchor(void)
{
	struct bus1_handle *anchor;

	anchor = kmalloc(sizeof(*anchor), GFP_KERNEL);
	if (!anchor)
		return ERR_PTR(-ENOMEM);

	bus1_handle_init(anchor);
	anchor->anchor = anchor;
	bus1_queue_node_init(&anchor->qnode, BUS1_MSG_NODE_RELEASE);
	anchor->node.map_handles = RB_ROOT;
	anchor->node.flags = 0;
	atomic_set(&anchor->node.n_strong, 0);

	return anchor;
}

/**
 * bus1_handle_new_remote() - allocate new remote handle
 * @other:			other handle to link to
 *
 * This allocates a new, fresh, remote handle for free use to the caller. The
 * handle will use the same anchor as @other (or @other in case it is an
 * anchor).
 *
 * Return: Pointer to handle, or ERR_PTR on failure.
 */
struct bus1_handle *bus1_handle_new_remote(struct bus1_handle *other)
{
	struct bus1_handle *remote;

	if (WARN_ON(!other))
		return ERR_PTR(-ENOTRECOVERABLE);

	remote = kmalloc(sizeof(*remote), GFP_KERNEL);
	if (!remote)
		return ERR_PTR(-ENOMEM);

	bus1_handle_init(remote);
	remote->anchor = bus1_handle_ref(other->anchor);
	bus1_queue_node_init(&remote->qnode, BUS1_MSG_NODE_DESTROY);
	RB_CLEAR_NODE(&remote->remote.rb_to_anchor);

	return remote;
}

/**
 * bus1_handle_free() - free handle
 * @k:		kref of handle to free
 *
 * This frees the handle belonging to the kref @k. It is meant to be used as
 * callback for kref_put(). The actual memory release is rcu-delayed so the
 * handle stays around at least until the next grace period.
 */
void bus1_handle_free(struct kref *k)
{
	struct bus1_handle *h = container_of(k, struct bus1_handle, ref);

	bus1_handle_deinit(h);
	kfree_rcu(h, qnode.rcu);
}

static struct bus1_peer *bus1_handle_acquire_holder(struct bus1_handle *handle)
{
	struct bus1_peer *peer = NULL;

	/*
	 * The holder of a handle is set during ATTACH and remains set until
	 * the handle is destroyed. This ACQUIRE pairs with the RELEASE during
	 * ATTACH, and guarantees handle->holder is non-NULL, if n_weak is set.
	 *
	 * We still need to do this under rcu-lock. During DETACH, n_weak drops
	 * to 0, and then may be followed by a kfree_rcu() on the peer. Hence,
	 * we guarantee that if we read n_weak > 0 and the holder in the same
	 * critical section, it must be accessible.
	 */
	rcu_read_lock();
	if (atomic_read_acquire(&handle->n_weak) > 0)
		peer = bus1_peer_acquire(lockless_dereference(handle->holder));
	rcu_read_unlock();

	return peer;
}

/**
 * bus1_handle_acquire_owner() - acquire owner of a handle
 * @handle:			handle to operate on
 *
 * This tries to acquire the owner of a handle. If the owner is already
 * detached, this will return NULL.
 *
 * Return: Pointer to owner on success, NULL on failure.
 */
struct bus1_peer *bus1_handle_acquire_owner(struct bus1_handle *handle)
{
	return bus1_handle_acquire_holder(handle->anchor);
}

static void bus1_handle_queue_release(struct bus1_handle *handle)
{
	struct bus1_handle *anchor = handle->anchor;
	struct bus1_peer *owner;

	if (test_bit(BUS1_HANDLE_BIT_RELEASED, &anchor->node.flags) ||
	    test_bit(BUS1_HANDLE_BIT_DESTROYED, &anchor->node.flags))
		return;

	owner = anchor->holder;
	lockdep_assert_held(&owner->data.lock);

	if (!bus1_queue_node_is_queued(&anchor->qnode)) {
		bus1_handle_ref(anchor);
		bus1_queue_commit_unstaged(&owner->data.queue, &owner->waitq,
					   &anchor->qnode);
	}
}

static void bus1_handle_flush_release(struct bus1_handle *handle)
{
	struct bus1_handle *anchor = handle->anchor;
	struct bus1_peer *owner;

	if (test_bit(BUS1_HANDLE_BIT_RELEASED, &anchor->node.flags) ||
	    test_bit(BUS1_HANDLE_BIT_DESTROYED, &anchor->node.flags))
		return;

	owner = anchor->holder;
	lockdep_assert_held(&owner->data.lock);

	if (bus1_queue_node_is_queued(&anchor->qnode)) {
		bus1_queue_remove(&owner->data.queue, &owner->waitq,
				  &anchor->qnode);
		bus1_handle_unref(anchor);
	}
}

/**
 * bus1_handle_ref_by_other() - lookup handle on a peer
 * @peer:		peer to lookup handle for
 * @handle:		other handle to match for
 *
 * This looks for an handle held by @peer, which points to the same node as
 * @handle (i.e., it is linked to @handle->anchor). If @peer does not hold such
 * a handle, this returns NULL. Otherwise, an object reference is acquired and
 * returned as pointer.
 *
 * The caller must hold an active reference to @peer.
 *
 * Return: Pointer to handle if found, NULL if not found.
 */
struct bus1_handle *bus1_handle_ref_by_other(struct bus1_peer *peer,
					     struct bus1_handle *handle)
{
	struct bus1_handle *h, *res = NULL;
	struct bus1_peer *owner = NULL;
	struct rb_node *n;

	/*
	 * We need to acquire the owner of @handle to iterate its tree. We do
	 * the exact same logic as bus1_handle_acquire_owner(), but fast-path
	 * the case were @peer matches the owner. In that case we can just ref
	 * the anchor itself, without temporarily acquiring the owner.
	 * See bus1_handle_acquire_owner() for details on the ACQUIRE/RELEASE
	 * semantics and barriers.
	 */
	rcu_read_lock();
	if (atomic_read_acquire(&handle->anchor->n_weak) > 0)
		owner = lockless_dereference(handle->anchor->holder);
	if (owner == peer) {
		rcu_read_unlock();
		return bus1_handle_ref(handle->anchor);
	}
	owner = bus1_peer_acquire(owner);
	rcu_read_unlock();
	if (!owner)
		return NULL;

	mutex_lock(&owner->data.lock);
	n = handle->anchor->node.map_handles.rb_node;
	while (n) {
		h = container_of(n, struct bus1_handle, remote.rb_to_anchor);
		if (peer < h->holder) {
			n = n->rb_left;
		} else if (peer > h->holder) {
			n = n->rb_right;
		} else /* if (peer == h->holder) */ {
			res = bus1_handle_ref(h);
			break;
		}
	}
	mutex_unlock(&owner->data.lock);

	bus1_peer_release(owner);
	return res;
}

static struct bus1_handle *bus1_handle_splice(struct bus1_handle *handle)
{
	struct bus1_queue_node *qnode = &handle->qnode;
	struct bus1_handle *h, *anchor = handle->anchor;
	struct rb_node *n, **slot;

	n = NULL;
	slot = &anchor->node.map_handles.rb_node;
	while (*slot) {
		n = *slot;
		h = container_of(n, struct bus1_handle, remote.rb_to_anchor);
		if (unlikely(handle->holder == h->holder)) {
			/* conflict detected; return ref to caller */
			return bus1_handle_ref(h);
		} else if (handle->holder < h->holder) {
			slot = &n->rb_left;
		} else /* if (handle->holder > h->holder) */ {
			slot = &n->rb_right;
		}
	}

	rb_link_node(&handle->remote.rb_to_anchor, n, slot);
	rb_insert_color(&handle->remote.rb_to_anchor,
			&anchor->node.map_handles);
	/* map_handles pins one ref of each entry */
	bus1_handle_ref(handle);

	/* join a possibly ongoing destruction */
	if (test_bit(BUS1_HANDLE_BIT_DESTROYED, &anchor->node.flags) &&
	    !qnode->group) {
		qnode->owner = bus1_peer_acquire(handle->holder);
		if (qnode->owner) {
			if (bus1_tx_join(&anchor->qnode, qnode))
				bus1_handle_ref(handle);
			else
				qnode->owner = bus1_peer_release(qnode->owner);
		}
	}

	return NULL;
}

/**
 * bus1_handle_acquire_locked() - acquire strong reference
 * @handle:		handle to operate on, or NULL
 * @holder:		holder of the handle
 * @strong:		whether to acquire a strong reference
 *
 * This is the same as bus1_handle_acquire_slow(), but requires the caller to
 * hold the data lock of @holder and the owner.
 *
 * Return: Acquired handle (possibly a conflict).
 */
struct bus1_handle *bus1_handle_acquire_locked(struct bus1_handle *handle,
					       struct bus1_peer *holder,
					       bool strong)
{
	struct bus1_handle *h, *anchor = handle->anchor;
	struct bus1_peer *owner = NULL;

	if (!test_bit(BUS1_HANDLE_BIT_RELEASED, &anchor->node.flags)) {
		owner = (handle == anchor) ? holder : anchor->holder;
		WARN_ON(!owner);
	}

	/*
	 * Verify the correct locks are held: If @handle is already attached,
	 * its holder must match @holder (otherwise, its holder must be NULL).
	 * In all cases, @holder must be locked.
	 * Additionally, the owner must be locked as well. However, the owner
	 * might be released already. The caller must guarantee that if the
	 * owner is not released, yet, it must be locked.
	 */
	WARN_ON(holder != (ACCESS_ONCE(handle->holder) ?: holder));
	lockdep_assert_held(&holder->data.lock);
	if (owner)
		lockdep_assert_held(&owner->data.lock);

	if (atomic_read(&handle->n_weak) == 0) {
		handle->holder = holder;

		if (test_bit(BUS1_HANDLE_BIT_RELEASED, &anchor->node.flags)) {
			/*
			 * When the node is already released, any attach ends
			 * up as stale handle. So nothing special to do here.
			 */
		} else if (handle == anchor) {
			/*
			 * Attach of an anchor: There is nothing to do, we
			 * simply verify the map is empty and continue.
			 */
			WARN_ON(!RB_EMPTY_ROOT(&handle->node.map_handles));
		} else if (owner) {
			/*
			 * Attach of a remote: If the node is not released,
			 * yet, we insert it into the lookup tree. Otherwise,
			 * we leave it around as stale handle. Note that
			 * tree-insertion might race. If a conflict is detected
			 * we drop this handle and restart with the conflict.
			 */
			h = bus1_handle_splice(handle);
			if (unlikely(h)) {
				bus1_handle_unref(handle);
				WARN_ON(atomic_read(&h->n_weak) != 1);
				return bus1_handle_acquire_locked(h, holder,
								  strong);
			}
		}

		bus1_handle_ref(handle);

		/*
		 * This RELEASE pairs with the ACQUIRE in
		 * bus1_handle_acquire_holder(). It simply guarantees that
		 * handle->holder is set before n_weak>0 is visible. It does
		 * not give any guarantees on the validity of the holder. All
		 * it does is guarantee it is non-NULL and will stay constant.
		 */
		atomic_set_release(&handle->n_weak, 1);
	} else {
		WARN_ON(atomic_inc_return(&handle->n_weak) < 1);
	}

	if (strong && atomic_inc_return(&anchor->node.n_strong) == 1)
		bus1_handle_flush_release(anchor);

	return handle;
}

/**
 * bus1_handle_acquire_slow() - slow-path of handle acquisition
 * @handle:		handle to acquire
 * @holder:		holder of the handle
 * @strong:		whether to acquire a strong reference
 *
 * This is the slow-path of bus1_handle_acquire(). See there for details.
 *
 * Return: Acquired handle (possibly a conflict).
 */
struct bus1_handle *bus1_handle_acquire_slow(struct bus1_handle *handle,
					     struct bus1_peer *holder,
					     bool strong)
{
	const bool is_anchor = (handle == handle->anchor);
	struct bus1_peer *owner;

	if (is_anchor)
		owner = holder;
	else
		owner = bus1_handle_acquire_owner(handle);

	bus1_mutex_lock2(&holder->data.lock,
			 owner ? &owner->data.lock : NULL);
	handle = bus1_handle_acquire_locked(handle, holder, strong);
	bus1_mutex_unlock2(&holder->data.lock,
			   owner ? &owner->data.lock : NULL);

	if (!is_anchor)
		bus1_peer_release(owner);

	return handle;
}

static void bus1_handle_release_locked(struct bus1_handle *h,
				       struct bus1_peer *owner,
				       bool strong)
{
	struct bus1_handle *t, *safe, *anchor = h->anchor;

	if (atomic_dec_return(&h->n_weak) == 0) {
		if (test_bit(BUS1_HANDLE_BIT_RELEASED, &anchor->node.flags)) {
			/*
			 * In case a node is already released, all its handles
			 * are already stale (and new handles are instantiated
			 * as stale). Nothing to do.
			 */
		} else if (h == anchor) {
			/*
			 * Releasing an anchor requires us to drop all remotes
			 * from the map. We do not detach them, though, we just
			 * clear the map and drop the pinned reference.
			 */
			WARN_ON(!owner);
			rbtree_postorder_for_each_entry_safe(t, safe,
							&h->node.map_handles,
							remote.rb_to_anchor) {
				RB_CLEAR_NODE(&t->remote.rb_to_anchor);
				/* drop reference held by link into map */
				bus1_handle_unref(t);
			}
			h->node.map_handles = RB_ROOT;
			bus1_handle_flush_release(h);
			set_bit(BUS1_HANDLE_BIT_RELEASED, &h->node.flags);
		} else if (!owner) {
			/*
			 * If an owner is disconnected, its nodes remain until
			 * the owner is drained. In that period, it is
			 * impossible for any handle-release to acquire, and
			 * thus lock, the owner. Therefore, if that happens we
			 * leave the handle linked and rely on the owner
			 * cleanup to flush them all.
			 *
			 * A side-effect of this is that the holder field must
			 * remain set, even though it must not be dereferenced
			 * as it is a stale pointer. This is required to keep
			 * the rbtree lookup working. Anyone dereferencing the
			 * holder of a remote must therefore either hold a weak
			 * reference or check for n_weak with the owner locked.
			 */
		} else if (!WARN_ON(RB_EMPTY_NODE(&h->remote.rb_to_anchor))) {
			rb_erase(&h->remote.rb_to_anchor,
				 &anchor->node.map_handles);
			RB_CLEAR_NODE(&h->remote.rb_to_anchor);
			/* drop reference held by link into map */
			bus1_handle_unref(h);
		}

		/* queue release after detach but before unref */
		if (strong && atomic_dec_return(&anchor->node.n_strong) == 0) {
			if (owner)
				bus1_handle_queue_release(anchor);
		}

		/*
		 * This is the reference held by n_weak>0 (or 'holder valid').
		 * Note that the holder-field will remain set and stale.
		 */
		bus1_handle_unref(h);
	} else if (strong && atomic_dec_return(&anchor->node.n_strong) == 0) {
		/* still weak refs left, only queue release notification */
		if (owner)
			bus1_handle_queue_release(anchor);
	}
}

/**
 * bus1_handle_release_slow() - slow-path of handle release
 * @handle:		handle to release
 * @strong:		whether to release a strong reference
 *
 * This is the slow-path of bus1_handle_release(). See there for details.
 */
void bus1_handle_release_slow(struct bus1_handle *handle, bool strong)
{
	const bool is_anchor = (handle == handle->anchor);
	struct bus1_peer *owner, *holder;

	/*
	 * Caller must own an active reference to the holder of @handle.
	 * Furthermore, since the caller also owns a weak reference to @handle
	 * we know that its holder cannot be NULL nor modified in parallel.
	 */
	holder = handle->holder;
	WARN_ON(!holder);
	lockdep_assert_held(&holder->active);

	if (is_anchor)
		owner = holder;
	else
		owner = bus1_handle_acquire_owner(handle);

	bus1_mutex_lock2(&holder->data.lock,
			 owner ? &owner->data.lock : NULL);
	bus1_handle_release_locked(handle, owner, strong);
	bus1_mutex_unlock2(&holder->data.lock,
			   owner ? &owner->data.lock : NULL);

	if (!is_anchor)
		bus1_peer_release(owner);
}

/**
 * bus1_handle_destroy_locked() - XXX
 */
void bus1_handle_destroy_locked(struct bus1_handle *handle, struct bus1_tx *tx)
{
	struct bus1_peer *owner = handle->holder;
	struct bus1_handle *t, *safe;

	if (WARN_ON(handle != handle->anchor || !owner))
		return;

	lockdep_assert_held(&owner->local.lock);
	lockdep_assert_held(&owner->data.lock);

	if (WARN_ON(test_and_set_bit(BUS1_HANDLE_BIT_DESTROYED,
				     &handle->node.flags)))
		return;

	/* flush release and reuse qnode for destruction */
	if (bus1_queue_node_is_queued(&handle->qnode)) {
		bus1_queue_remove(&owner->data.queue, &owner->waitq,
				  &handle->qnode);
		bus1_handle_unref(handle);
	}
	bus1_queue_node_deinit(&handle->qnode);
	bus1_queue_node_init(&handle->qnode, BUS1_MSG_NODE_DESTROY);

	bus1_tx_stage_sync(tx, &handle->qnode);
	bus1_handle_ref(handle);

	/* collect all handles in the transaction */
	rbtree_postorder_for_each_entry_safe(t, safe,
					     &handle->node.map_handles,
					     remote.rb_to_anchor) {
		if (WARN_ON(t->qnode.group))
			continue;

		t->qnode.owner = bus1_handle_acquire_holder(t);
		if (t->qnode.owner) {
			bus1_tx_stage_later(tx, &t->qnode);
			bus1_handle_ref(t);
		}
	}
}

/**
 * bus1_handle_is_live_at() - check whether handle is live at a given time
 * @h:				handle to check
 * @timestamp:			timestamp to check
 *
 * This checks whether the handle @h is live at the time of @timestamp. The
 * caller must make sure that @timestamp was acquired on the clock of the
 * holder of @h.
 *
 * Note that this does not synchronize on the node owner. That is, usually you
 * want to call this at the time of RECV, so it is guaranteed that there is no
 * staging message in front of @timestamp. Otherwise, a node owner might
 * acquire a commit-timestamp for the destruction of @h lower than @timestamp.
 *
 * The caller must hold the data-lock of the holder of @h.
 *
 * Return: True if live at the given timestamp, false if destroyed.
 */
bool bus1_handle_is_live_at(struct bus1_handle *h, u64 timestamp)
{
	u64 ts;

	WARN_ON(timestamp & 1);
	lockdep_assert_held(&h->holder->data.lock);

	if (!test_bit(BUS1_HANDLE_BIT_DESTROYED, &h->anchor->node.flags))
		return true;

	ts = bus1_queue_node_get_timestamp(&h->qnode);
	return (ts == 0) || (ts & 1) || (timestamp <= ts);
}

/**
 * bus1_handle_import() - XXX
 */
struct bus1_handle *bus1_handle_import(struct bus1_peer *peer,
				       u64 id,
				       bool *is_newp)
{
	struct bus1_handle *h;
	struct rb_node *n, **slot;

	lockdep_assert_held(&peer->local.lock);

	n = NULL;
	slot = &peer->local.map_handles.rb_node;
	while (*slot) {
		n = *slot;
		h = container_of(n, struct bus1_handle, rb_to_peer);
		if (id < h->id) {
			slot = &n->rb_left;
		} else if (id > h->id) {
			slot = &n->rb_right;
		} else /* if (id == h->id) */ {
			*is_newp = false;
			return bus1_handle_ref(h);
		}
	}

	if (id & (BUS1_HANDLE_FLAG_MANAGED | BUS1_HANDLE_FLAG_REMOTE))
		return ERR_PTR(-ENXIO);

	h = bus1_handle_new_anchor();
	if (IS_ERR(h))
		return ERR_CAST(h);

	h->id = id;
	bus1_handle_ref(h);
	rb_link_node(&h->rb_to_peer, n, slot);
	rb_insert_color(&h->rb_to_peer, &peer->local.map_handles);

	*is_newp = true;
	return h;
}

/**
 * bus1_handle_identify() - XXX
 */
u64 bus1_handle_identify(struct bus1_handle *h)
{
	WARN_ON(!h->holder);
	lockdep_assert_held(&h->holder->local.lock);

	if (h->id == BUS1_HANDLE_INVALID) {
		h->id = ++h->holder->local.handle_ids << 3;
		h->id |= BUS1_HANDLE_FLAG_MANAGED;
		if (h != h->anchor)
			h->id |= BUS1_HANDLE_FLAG_REMOTE;
	}

	return h->id;
}

/**
 * bus1_handle_export() - XXX
 */
void bus1_handle_export(struct bus1_handle *handle)
{
	struct bus1_handle *h;
	struct rb_node *n, **slot;

	/*
	 * The caller must own a weak reference to @handle when calling this.
	 * Hence, we know that its holder is valid. Also verify that the caller
	 * holds the required active reference and local lock.
	 */
	WARN_ON(!handle->holder);
	lockdep_assert_held(&handle->holder->active);
	lockdep_assert_held(&handle->holder->local.lock);

	if (RB_EMPTY_NODE(&handle->rb_to_peer)) {
		bus1_handle_identify(handle);

		n = NULL;
		slot = &handle->holder->local.map_handles.rb_node;
		while (*slot) {
			n = *slot;
			h = container_of(n, struct bus1_handle, rb_to_peer);
			if (WARN_ON(handle->id == h->id))
				return;
			else if (handle->id < h->id)
				slot = &n->rb_left;
			else /* if (handle->id > h->id) */
				slot = &n->rb_right;
		}

		bus1_handle_ref(handle);
		rb_link_node(&handle->rb_to_peer, n, slot);
		rb_insert_color(&handle->rb_to_peer,
				&handle->holder->local.map_handles);
	}
}

static void bus1_handle_forget_internal(struct bus1_peer *peer,
					struct bus1_handle *h,
					bool erase_rb)
{
	/*
	 * The passed handle might not have any weak references. Hence, we
	 * require the caller to pass the holder explicitly as @peer. However,
	 * if @handle has weak references, we want to WARN if it does not match
	 * @peer. Since this is unlocked, we use ACCESS_ONCE() here to get a
	 * consistent value. This is purely for debugging.
	 */
	WARN_ON(peer != (ACCESS_ONCE(h->holder) ?: peer));
	lockdep_assert_held(&peer->local.lock);

	if (bus1_handle_is_public(h) || RB_EMPTY_NODE(&h->rb_to_peer))
		return;

	if (erase_rb)
		rb_erase(&h->rb_to_peer, &peer->local.map_handles);
	RB_CLEAR_NODE(&h->rb_to_peer);
	h->id = BUS1_HANDLE_INVALID;
	bus1_handle_unref(h);
}

/**
 * bus1_handle_forget() - forget handle
 * @peer:			holder of the handle
 * @h:				handle to operate on, or NULL
 *
 * If @h is not public, but linked into the ID-lookup tree, this will remove it
 * from the tree and clear the ID of @h. It basically undoes what
 * bus1_handle_import() and bus1_handle_export() do.
 */
void bus1_handle_forget(struct bus1_peer *peer, struct bus1_handle *h)
{
	if (h)
		bus1_handle_forget_internal(peer, h, true);
}

/**
 * bus1_handle_forget_keep() - forget handle but keep rb-tree order
 * @peer:			holder of the handle
 * @h:				handle to operate on, or NULL
 *
 * This is like bus1_handle_forget(), but does not modify the ID-namespace
 * rb-tree. That is, the backlink in @h is cleared (h->rb_to_peer), but the
 * rb-tree is not rebalanced. As such, you can use it with
 * rbtree_postorder_for_each_entry_safe() to drop all entries.
 */
void bus1_handle_forget_keep(struct bus1_peer *peer, struct bus1_handle *h)
{
	if (h)
		bus1_handle_forget_internal(peer, h, false);
}
