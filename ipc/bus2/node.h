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

struct bus1_peer;
struct bus1_tx;

/**
 * struct bus1_handle - XXX
 */
struct bus1_handle {
	struct kref ref;
	atomic_t n_inflight;
	atomic_t n_user;
	struct bus1_peer *holder;
	struct bus1_handle *anchor;
	struct rb_node rb_to_peer;
	u64 id;
	union {
		struct rcu_head rcu;
		struct {
			struct rb_root map_handles;
			struct bus1_handle *release_pin;
		} node;
		struct {
			struct rb_node rb_to_anchor;
		} remote;
	};
};

struct bus1_handle *bus1_handle_new_anchor(void);
struct bus1_handle *bus1_handle_new_remote(struct bus1_handle *handle);
void bus1_handle_free(struct kref *ref);

struct bus1_handle *bus1_handle_ref_by_other(struct bus1_peer *peer,
					     struct bus1_handle *handle);
struct bus1_handle *bus1_handle_acquire_slow(struct bus1_handle *handle,
					     struct bus1_peer *holder);
void bus1_handle_release_slow(struct bus1_handle *h, struct bus1_tx *tx);

/**
 * bus1_handle_ref() - XXX
 */
static inline struct bus1_handle *bus1_handle_ref(struct bus1_handle *handle)
{
	if (handle)
		kref_get(&handle->ref);
	return handle;
}

/**
 * bus1_handle_unref() - XXX
 */
static inline struct bus1_handle *bus1_handle_unref(struct bus1_handle *handle)
{
	if (handle)
		kref_put(&handle->ref, bus1_handle_free);
	return NULL;
}

/**
 * bus1_handle_acquire() - XXX
 */
static inline struct bus1_handle *
bus1_handle_acquire(struct bus1_handle *handle, struct bus1_peer *holder)
{
	int n, t;

	if (handle) {
		/* threshold for anchors is +1 to flush release */
		t = 1 + !!(handle == handle->anchor);
		n = bus1_atomic_add_if_ge(&handle->n_inflight, 1, t);
		if (n < t)
			handle = bus1_handle_acquire_slow(handle, holder);
	}
	return handle;
}

/**
 * bus1_handle_release() - XXX
 */
static inline struct bus1_handle *
bus1_handle_release(struct bus1_handle *handle, struct bus1_tx *tx)
{
	int n, t;

	if (handle) {
		/* threshold for anchors is +1 to trigger release */
		t = 2 + !!(handle == handle->anchor);
		n = bus1_atomic_add_if_ge(&handle->n_inflight, -1, t);
		if (n < t)
			bus1_handle_release_slow(handle, tx);
	}
	return NULL;
}

#endif /* __BUS1_NODE_H */
