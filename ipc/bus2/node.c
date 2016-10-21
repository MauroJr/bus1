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
#include "node.h"
#include "peer.h"
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
	WARN_ON(h->id != BUS1_HANDLE_INVALID);
	WARN_ON(!RB_EMPTY_NODE(&h->rb_to_peer));
	WARN_ON(h->tlink);
	WARN_ON(h->holder);
	WARN_ON(atomic_read(&h->n_user) != 0);
	WARN_ON(atomic_read(&h->n_weak) != 0);
}

/**
 * bus1_handle_new_anchor() - XXX
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
 * bus1_handle_new_remote() - XXX
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
	kfree_rcu(h, rcu);
}

static void bus1_handle_set_holder(struct bus1_handle *handle,
				   struct bus1_peer *peer)
{
	/*
	 * XXX
	 */
	smp_store_release(&handle->holder, peer);
}

static struct bus1_peer *bus1_handle_acquire_holder(struct bus1_handle *handle)
{
	struct bus1_peer *peer;

	/*
	 * Fetch the holder of a handle. We know that if it is valid, it will
	 * remain accessible for at least one grace-period, which we use to
	 * acquire it.
	 * However, holders might be stale in case a release could not clear
	 * them. Hence, we must verify that the handle is in use before
	 * dereferencing it. See the comment in handle-release for details.
	 */
	rcu_read_lock();
	peer = smp_load_acquire(&handle->holder);
	if (atomic_read(&handle->n_weak) > 0)
		peer = bus1_peer_acquire(peer);
	else
		peer = NULL;
	rcu_read_unlock();

	return peer;
}

static struct bus1_peer *bus1_handle_acquire_owner(struct bus1_handle *handle)
{
	struct bus1_peer *peer;

	/*
	 * Fetch the owner of a handle. We know that if it is non-NULL, it is
	 * valid for at least one grace-period. We simply try to acquire it in
	 * that period. If it fails, we return NULL, otherwise, we now have the
	 * owner pinned and can make use of it.
	 */
	rcu_read_lock();
	peer = bus1_peer_acquire(smp_load_acquire(&handle->anchor->holder));
	rcu_read_unlock();

	return peer;
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
	struct bus1_peer *owner;
	struct rb_node *n;

	/*
	 * Get a valid snapshot of the owner pointer. If it is non-NULL, we are
	 * guaranteed for it to stay valid for once grace-period. So try
	 * acquiring it so we can pin it. In case it matches the anchor, we can
	 * skip this and just return it, since it is the same as the calling
	 * context.
	 */
	rcu_read_lock();
	owner = smp_load_acquire(&handle->anchor->holder);
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

static struct bus1_handle *bus1_handle_splice(struct bus1_handle *handle,
					      struct bus1_peer *holder)
{
	struct bus1_handle *h;
	struct rb_node *n, **slot;

	n = NULL;
	slot = &handle->anchor->node.map_handles.rb_node;
	while (*slot) {
		n = *slot;
		h = container_of(n, struct bus1_handle, remote.rb_to_anchor);
		if (unlikely(holder == h->holder)) {
			/* conflict detected; return ref to caller */
			return bus1_handle_ref(h);
		} else if (holder < h->holder) {
			slot = &n->rb_left;
		} else /* if (holder > h->holder) */ {
			slot = &n->rb_right;
		}
	}

	/* set stale pointer for tree integrity */
	bus1_handle_set_holder(handle, holder);

	rb_link_node(&handle->remote.rb_to_anchor, n, slot);
	rb_insert_color(&handle->remote.rb_to_anchor,
			&handle->anchor->node.map_handles);
	/* map_handles pins one ref of each entry */
	bus1_handle_ref(handle);

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
			h = bus1_handle_splice(handle, holder);
			if (unlikely(h)) {
				bus1_handle_unref(handle);
				WARN_ON(atomic_read(&h->n_weak) != 1);
				return bus1_handle_acquire_locked(h, holder,
								  strong);
			}
		}

		bus1_handle_set_holder(handle, holder);
		bus1_handle_ref(handle);
	}

	WARN_ON(atomic_inc_return(&handle->n_weak) < 1);

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
			 * In case we have stale holders on those remotes, we
			 * must clear it. See below.
			 */
			WARN_ON(!owner);
			rbtree_postorder_for_each_entry_safe(t, safe,
							&h->node.map_handles,
							remote.rb_to_anchor) {
				RB_CLEAR_NODE(&t->remote.rb_to_anchor);
				if (atomic_read(&t->n_weak) == 0)
					bus1_handle_set_holder(t, NULL);
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
		 * Note that the holder-field might remain set and stale in
		 * case the owner is already disconnected, but has not dropped
		 * its nodes.
		 */
		if (owner ||
		    test_bit(BUS1_HANDLE_BIT_RELEASED, &anchor->node.flags))
			bus1_handle_set_holder(h, NULL);
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
	struct bus1_peer *holder, *owner = handle->holder;
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
	/* XXX: stage as multicast on @tx */
	bus1_queue_commit_unstaged(&owner->data.queue, &owner->waitq,
				   &handle->qnode);
	bus1_handle_ref(handle);

	/* collect all handles in the transaction */
	rbtree_postorder_for_each_entry_safe(t, safe,
					     &handle->node.map_handles,
					     remote.rb_to_anchor) {
		holder = bus1_handle_acquire_holder(t);
		if (!holder)
			continue;

		/* XXX: collect destruction notifications on @tx */
		bus1_peer_release(holder);
	}
}

/**
 * bus1_handle_import() - XXX
 */
struct bus1_handle *bus1_handle_import(struct bus1_peer *peer, u64 id)
{
	struct bus1_handle *h;
	struct rb_node *n, **slot;

	lockdep_assert_held(&peer->local.lock);

	n = NULL;
	slot = &peer->local.map_handles.rb_node;
	while (*slot) {
		n = *slot;
		h = container_of(n, struct bus1_handle, rb_to_peer);
		if (id < h->id)
			slot = &n->rb_left;
		else if (id > h->id)
			slot = &n->rb_right;
		else /* if (id == h->id) */
			return bus1_handle_ref(h);
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

	return h;
}

/**
 * bus1_handle_export() - XXX
 */
bool bus1_handle_export(struct bus1_handle *handle, u64 timestamp)
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

	/* XXX: bail out if @timestamp is after destruction */

	if (RB_EMPTY_NODE(&handle->rb_to_peer)) {
		WARN_ON(handle->id != BUS1_HANDLE_INVALID);
		handle->id = ++handle->holder->local.handle_ids << 3;
		handle->id |= BUS1_HANDLE_FLAG_MANAGED;
		if (handle != handle->anchor)
			handle->id |= BUS1_HANDLE_FLAG_REMOTE;

		n = NULL;
		slot = &handle->holder->local.map_handles.rb_node;
		while (*slot) {
			n = *slot;
			h = container_of(n, struct bus1_handle, rb_to_peer);
			if (WARN_ON(handle->id == h->id))
				return false;
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

	return true;
}

/**
 * bus1_handle_forget() - XXX
 */
void bus1_handle_forget(struct bus1_peer *peer, struct bus1_handle *h)
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

	rb_erase(&h->rb_to_peer, &peer->local.map_handles);
	RB_CLEAR_NODE(&h->rb_to_peer);
	h->id = BUS1_HANDLE_INVALID;
	bus1_handle_unref(h);
}
