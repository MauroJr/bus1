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

static void bus1_handle_init(struct bus1_handle *handle)
{
	kref_init(&handle->ref);
	atomic_set(&handle->n_inflight, -1);
	atomic_set(&handle->n_user, 0);
	handle->holder = NULL;
	handle->anchor = NULL;
	RB_CLEAR_NODE(&handle->rb_to_peer);
	handle->id = BUS1_HANDLE_INVALID;
}

static void bus1_handle_deinit(struct bus1_handle *handle)
{
	if (handle == handle->anchor) {
		WARN_ON(!IS_ERR_OR_NULL(handle->node.release_pin));
		WARN_ON(!RB_EMPTY_ROOT(&handle->node.map_handles));
	} else if (handle->anchor) {
		WARN_ON(!RB_EMPTY_NODE(&handle->remote.rb_to_anchor));
		bus1_handle_unref(handle->anchor);
	}

	WARN_ON(!RB_EMPTY_NODE(&handle->rb_to_peer));
	WARN_ON(handle->holder);
	WARN_ON(atomic_read(&handle->n_user) != 0);
	WARN_ON(atomic_read(&handle->n_inflight) > 0);
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
	anchor->node.map_handles = RB_ROOT;
	anchor->node.release_pin = NULL;

	return anchor;
}

/**
 * bus1_handle_new_remote() - XXX
 */
struct bus1_handle *bus1_handle_new_remote(struct bus1_handle *handle)
{
	struct bus1_handle *remote;

	if (WARN_ON(!handle))
		return ERR_PTR(-ENOTRECOVERABLE);

	remote = kmalloc(sizeof(*remote), GFP_KERNEL);
	if (!remote)
		return ERR_PTR(-ENOMEM);

	bus1_handle_init(remote);
	remote->anchor = bus1_handle_ref(handle->anchor);
	RB_CLEAR_NODE(&remote->remote.rb_to_anchor);

	return remote;
}

/**
 * bus1_handle_free() - XXX
 */
void bus1_handle_free(struct kref *k)
{
	struct bus1_handle *handle = container_of(k, struct bus1_handle, ref);

	bus1_handle_deinit(handle);
	kfree_rcu(handle, rcu);
}

static struct bus1_peer *bus1_handle_get_holder(struct bus1_handle *handle)
{
	return smp_load_acquire(&handle->holder);
}

static void bus1_handle_set_holder(struct bus1_handle *handle,
				   struct bus1_peer *peer)
{
	smp_store_release(&handle->holder, peer);
}

static struct bus1_peer *bus1_handle_acquire_holder(struct bus1_handle *handle)
{
	struct bus1_peer *peer;

	rcu_read_lock();
	peer = bus1_peer_acquire(bus1_handle_get_holder(handle));
	rcu_read_unlock();

	return peer;
}

static struct bus1_peer *bus1_handle_get_owner(struct bus1_handle *handle)
{
	return bus1_handle_get_holder(handle->anchor);
}

static struct bus1_peer *bus1_handle_acquire_owner(struct bus1_handle *handle)
{
	return bus1_handle_acquire_holder(handle->anchor);
}

static void bus1_handle_queue_release(struct bus1_handle *handle,
				      struct bus1_tx *tx)
{
	struct bus1_handle *anchor = handle->anchor;

	/* both handle->holder and anchor->holder must be locked */

	if (likely(!anchor->holder ||
		   !IS_ERR_OR_NULL(anchor->node.release_pin) ||
		   !RB_EMPTY_ROOT(&anchor->node.map_handles) ||
		   atomic_read(&anchor->n_inflight) != 1))
		return;

	/* XXX: actually queue the message */
	anchor->node.release_pin = bus1_handle_ref(handle);
}

static void bus1_handle_flush_release(struct bus1_handle *handle)
{
	struct bus1_handle *anchor = handle->anchor;

	/* both handle->holder and anchor->holder must be locked */

	if (likely(IS_ERR_OR_NULL(anchor->node.release_pin)))
		return;

	/* XXX: actually dequeue the message */
	anchor->node.release_pin = bus1_handle_unref(anchor->node.release_pin);
}

/**
 * bus1_handle_ref_by_other() - XXX
 */
struct bus1_handle *bus1_handle_ref_by_other(struct bus1_peer *peer,
					     struct bus1_handle *handle)
{
	struct bus1_handle *h, *res = NULL;
	struct bus1_peer *owner;
	struct rb_node *n;

	rcu_read_lock();
	owner = bus1_handle_get_owner(handle);
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
			/*
			 * We found a conflict, some other attach-op raced us.
			 * Drop our own handle and switch to the conflict.
			 */
			WARN_ON(atomic_dec_return(&handle->n_inflight) != 0);
			bus1_handle_unref(handle);
			WARN_ON(atomic_inc_return(&h->n_inflight) < 2);
			return bus1_handle_ref(h);
		} else if (holder < h->holder) {
			slot = &n->rb_left;
		} else /* if (holder > h->holder) */ {
			slot = &n->rb_right;
		}
	}

	bus1_handle_set_holder(handle, holder);
	bus1_handle_ref(handle);

	rb_link_node(&handle->remote.rb_to_anchor, n, slot);
	rb_insert_color(&handle->remote.rb_to_anchor,
			&handle->anchor->node.map_handles);

	return handle;
}

static struct bus1_handle *
bus1_handle_acquire_locked(struct bus1_handle *handle,
			   struct bus1_peer *holder)
{
	int n_inflight;

	n_inflight = atomic_inc_return(&handle->n_inflight);
	if (WARN_ON(n_inflight < 0))
		return bus1_handle_unref(handle);

	/* flush possible release notification */
	bus1_handle_flush_release(handle);

	/* bail out early if already attached */
	if (n_inflight > 1)
		return handle;

	if (handle == handle->anchor) {
		/* anchor re-attach is impossible; their detach is final */
		WARN_ON(!RB_EMPTY_ROOT(&handle->node.map_handles));
		WARN_ON(atomic_inc_return(&handle->n_inflight) != 1);
		bus1_handle_set_holder(handle, holder);
		bus1_handle_ref(handle);
	} else {
		/* XXX: detach release-notification on re-attach */
		if (n_inflight == 0)
			WARN_ON(atomic_inc_return(&handle->n_inflight) != 1);

		handle = bus1_handle_splice(handle, holder);
	}

	return handle;
}

/**
 * bus1_handle_acquire_slow() - slow-path of handle acquisition
 * @handle:		handle to acquire
 * @holder:		holder of the handle
 *
 * This is the slow-path of bus1_handle_acquire(). See there for details.
 *
 * Return: Acquired handle (possibly a conflict), or NULL.
 */
struct bus1_handle *bus1_handle_acquire_slow(struct bus1_handle *handle,
					     struct bus1_peer *holder)
{
	const bool is_anchor = (handle == handle->anchor);
	struct bus1_peer *owner;

	if (is_anchor)
		owner = holder;
	else
		owner = bus1_handle_acquire_owner(handle);

	if (owner) {
		/*
		 * You are allowed to attach if the owner is still valid (must
		 * be checked under lock again), or if this attaches the anchor
		 * itself. However, anchor re-attach is prevented.
		 */
		bus1_mutex_lock2(&holder->data.lock, &owner->data.lock);
		if (handle->anchor->holder ||
		    (is_anchor && atomic_read(&handle->n_inflight) == -1))
			handle = bus1_handle_acquire_locked(handle, holder);
		else
			handle = bus1_handle_unref(handle);
		bus1_mutex_unlock2(&holder->data.lock, &owner->data.lock);
	} else {
		handle = bus1_handle_unref(handle);
	}

	if (!is_anchor)
		bus1_peer_release(owner);

	return handle;
}

static void bus1_handle_sever(struct bus1_handle *handle)
{
	struct bus1_handle *h, *t;

	if (handle == handle->anchor) {
		rbtree_postorder_for_each_entry_safe(h, t,
					&handle->node.map_handles,
					remote.rb_to_anchor)
			RB_CLEAR_NODE(&h->remote.rb_to_anchor);
		handle->node.map_handles = RB_ROOT;
		bus1_handle_flush_release(handle);
	} else if (handle->anchor->holder) {
		WARN_ON(RB_EMPTY_NODE(&handle->remote.rb_to_anchor));
		rb_erase(&handle->remote.rb_to_anchor,
			 &handle->anchor->node.map_handles);
		RB_CLEAR_NODE(&handle->remote.rb_to_anchor);
	}

	bus1_handle_set_holder(handle, NULL);
}

static void bus1_handle_release_locked(struct bus1_handle *handle,
				       struct bus1_tx *tx)
{
	int n_inflight;

	n_inflight = atomic_dec_return(&handle->n_inflight);
	if (WARN_ON(n_inflight < 0))
		return;

	if (n_inflight == 0) {
		bus1_handle_sever(handle);
		bus1_handle_unref(handle);
	}

	/* queue release notification, if this was the second-to-last ref */
	bus1_handle_queue_release(handle, tx);
}

/**
 * bus1_handle_release_slow() - slow-path of handle release
 * @handle:		handle to release
 * @tx:			current transaction
 *
 * This is the slow-path of bus1_handle_release(). See there for details.
 */
void bus1_handle_release_slow(struct bus1_handle *handle, struct bus1_tx *tx)
{
	const bool is_anchor = (handle == handle->anchor);
	struct bus1_peer *owner, *holder;

	holder = bus1_handle_get_holder(handle);
	WARN_ON(!holder);

	if (is_anchor)
		owner = holder;
	else
		owner = bus1_handle_acquire_owner(handle);

	bus1_mutex_lock2(&holder->data.lock,
			 owner ? &owner->data.lock : NULL);
	bus1_handle_release_locked(handle, tx);
	bus1_mutex_unlock2(&holder->data.lock,
			   owner ? &owner->data.lock : NULL);

	if (!is_anchor)
		bus1_peer_release(owner);
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

	if (id & BUS1_HANDLE_FLAG_REMOTE)
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
 * bus1_handle_drop() - XXX
 */
void bus1_handle_drop(struct bus1_peer *peer, struct bus1_handle *handle)
{
	struct bus1_peer *p;

	if (WARN_ON(RB_EMPTY_NODE(&handle->rb_to_peer)))
		return;

	p = bus1_handle_get_holder(handle);
	WARN_ON(p && p != peer);
	lockdep_assert_held(&peer->local.lock);

	rb_erase(&handle->rb_to_peer, &peer->local.map_handles);
	RB_CLEAR_NODE(&handle->rb_to_peer);
	handle->id = BUS1_HANDLE_INVALID;
}

/**
 * bus1_handle_export() - XXX
 */
bool bus1_handle_export(struct bus1_handle *handle, u64 timestamp)
{
	struct bus1_peer *peer;
	struct bus1_handle *h;
	struct rb_node *n, **slot;

	peer = bus1_handle_get_holder(handle);
	WARN_ON(!peer);
	lockdep_assert_held(&peer->local.lock);

	/* XXX: bail out if @timestamp is after destruction */

	if (RB_EMPTY_NODE(&handle->rb_to_peer)) {
		WARN_ON(handle->id != BUS1_HANDLE_INVALID);
		WARN_ON(handle == handle->anchor);
		handle->id = (++peer->local.handle_ids << 3) |
			     BUS1_HANDLE_FLAG_REMOTE |
			     BUS1_HANDLE_FLAG_MANAGED;

		n = NULL;
		slot = &peer->local.map_handles.rb_node;
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
		rb_insert_color(&handle->rb_to_peer, &peer->local.map_handles);
	}

	return true;
}
