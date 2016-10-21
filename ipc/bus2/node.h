#ifndef __BUS1_NODE_H
#define __BUS1_NODE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * XXX
 */

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/rbtree.h>
#include "util.h"
#include "util/queue.h"

struct bus1_peer;
struct bus1_tx;

/**
 * enum bus1_handle_bits - node flags
 * XXX
 */
enum bus1_handle_bits {
	BUS1_HANDLE_BIT_RELEASED,
	BUS1_HANDLE_BIT_DESTROYED,
};

/**
 * struct bus1_handle - object handle
 * XXX
 */
struct bus1_handle {
	struct kref ref;
	atomic_t n_weak;
	atomic_t n_user;
	struct bus1_peer *holder;
	struct bus1_handle *anchor;
	struct bus1_handle *tlink;
	struct rb_node rb_to_peer;
	u64 id;
	struct bus1_queue_node qnode;
	union {
		struct rcu_head rcu;
		struct {
			struct rb_root map_handles;
			unsigned long flags;
			atomic_t n_strong;
		} node;
		struct {
			struct rb_node rb_to_anchor;
		} remote;
	};
};

struct bus1_handle *bus1_handle_new_anchor(void);
struct bus1_handle *bus1_handle_new_remote(struct bus1_handle *other);
void bus1_handle_free(struct kref *ref);

struct bus1_handle *bus1_handle_ref_by_other(struct bus1_peer *peer,
					     struct bus1_handle *handle);

struct bus1_handle *bus1_handle_acquire_slow(struct bus1_handle *handle,
					     struct bus1_peer *holder,
					     bool strong);
struct bus1_handle *bus1_handle_acquire_locked(struct bus1_handle *handle,
					       struct bus1_peer *holder,
					       bool strong);
void bus1_handle_release_slow(struct bus1_handle *h, bool strong);

void bus1_handle_destroy_locked(struct bus1_handle *h, struct bus1_tx *tx);

struct bus1_handle *bus1_handle_import(struct bus1_peer *peer, u64 id);
bool bus1_handle_export(struct bus1_handle *h, u64 timestamp);
void bus1_handle_forget(struct bus1_peer *peer, struct bus1_handle *h);

/**
 * bus1_handle_is_anchor() - check whether handle is an anchor
 * @h:			handle to check
 *
 * This checks whether @h is an anchor. That is, @h was created via
 * bus1_handle_new_anchor(), rather than via bus1_handle_new_remote().
 *
 * Return: True if it is an anchor, false if not.
 */
static inline bool bus1_handle_is_anchor(struct bus1_handle *h)
{
	return h == h->anchor;
}

/**
 * bus1_handle_is_live() - check whether handle is live
 * @h:			handle to check
 *
 * This checks whether the given handle is still live. That is, its anchor was
 * not destroyed, yet.
 *
 * Return: True if it is live, false if already destroyed.
 */
static inline bool bus1_handle_is_live(struct bus1_handle *h)
{
	return !test_bit(BUS1_HANDLE_BIT_DESTROYED, &h->anchor->node.flags);
}

/**
 * bus1_handle_is_public() - check whether handle is public
 * @h:			handle to check
 *
 * This checks whether the given handle is public. That is, it was exported to
 * user-space and at least one public reference is left.
 *
 * Return: True if it is public, false if not.
 */
static inline bool bus1_handle_is_public(struct bus1_handle *h)
{
	return atomic_read(&h->n_user) > 0;
}

/**
 * bus1_handle_ref() - acquire object reference
 * @h:			handle to operate on, or NULL
 *
 * This acquires an object reference to @h. The caller must already hold a
 * reference. Otherwise, the behavior is undefined.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @h is returned.
 */
static inline struct bus1_handle *bus1_handle_ref(struct bus1_handle *h)
{
	if (h)
		kref_get(&h->ref);
	return h;
}

/**
 * bus1_handle_unref() - release object reference
 * @h:			handle to operate on, or NULL
 *
 * This releases an object reference. If the reference count drops to 0, the
 * object is released (rcu-delayed).
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_handle *bus1_handle_unref(struct bus1_handle *h)
{
	if (h)
		kref_put(&h->ref, bus1_handle_free);
	return NULL;
}

/**
 * bus1_handle_acquire() - acquire weak/strong reference
 * @h:			handle to operate on, or NULL
 * @holder:		holder of the handle
 * @strong:		whether to acquire a strong reference
 *
 * This acquires a weak/strong reference to the node @h is attached to.
 * This always succeeds. However, if a conflict is detected, @h is
 * unreferenced and the conflicting handle is returned (with an object
 * reference taken and strong reference acquired).
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: Pointer to the acquired handle is returned.
 */
static inline struct bus1_handle *
bus1_handle_acquire(struct bus1_handle *h,
		    struct bus1_peer *holder,
		    bool strong)
{
	if (h) {
		if (bus1_atomic_add_if_ge(&h->n_weak, 1, 1) < 1) {
			h = bus1_handle_acquire_slow(h, holder, strong);
		} else if (bus1_atomic_add_if_ge(&h->anchor->node.n_strong,
						 1, 1) < 1) {
			WARN_ON(h != bus1_handle_acquire_slow(h, holder,
							      strong));
			WARN_ON(atomic_dec_return(&h->n_weak) < 1);
		}
	}
	return h;
}

/**
 * bus1_handle_release() - release strong reference
 * @h:			handle to operate on, or NULL
 * @strong:		whether to release a strong reference
 *
 * This releases a strong reference to the node @h is attached to.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_handle *
bus1_handle_release(struct bus1_handle *h, bool strong)
{
	if (h) {
		if (strong &&
		    bus1_atomic_add_if_ge(&h->anchor->node.n_strong, -1, 2) < 2)
			bus1_handle_release_slow(h, true);
		else if (bus1_atomic_add_if_ge(&h->n_weak, -1, 2) < 2)
			bus1_handle_release_slow(h, false);
	}
	return NULL;
}

#endif /* __BUS1_NODE_H */
