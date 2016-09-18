#ifndef __BUS1_UTIL_H
#define __BUS1_UTIL_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * Utilities
 *
 * Random utility functions that don't belong to a specific object. Some of
 * them are copies from internal kernel functions (which lack an export
 * annotation), some of them are variants of internal kernel functions, and
 * some of them are our own.
 */

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/types.h>

struct dentry;
struct iovec;

int bus1_import_vecs(struct iovec *out_vecs,
		     size_t *out_length,
		     const void __user *vecs,
		     size_t n_vecs);
struct file *bus1_import_fd(int fd);

#if defined(CONFIG_DEBUG_FS)

struct dentry *
bus1_debugfs_create_atomic_x(const char *name,
			     umode_t mode,
			     struct dentry *parent,
			     atomic_t *value);

#else

static inline struct dentry *
bus1_debugfs_create_atomic_x(const char *name,
			     umode_t mode,
			     struct dentry *parent,
			     atomic_t *value)
{
	return ERR_PTR(-ENODEV);
}

#endif

/**
 * bus1_atomic_add_if_ge() - add, if above threshold
 * @a:		atomic_t to operate on
 * @add:	value to add
 * @t:		threshold
 *
 * Atomically add @add to @a, if @a is greater than, or equal to, @t.
 *
 * If [a + add] triggers an overflow, the operation is undefined. The caller
 * must verify that this cannot happen.
 *
 * Return: The old value of @a is returned.
 */
static inline int bus1_atomic_add_if_ge(atomic_t *a, int add, int t)
{
	int v, v1;

	for (v = atomic_read(a); v >= t; v = v1) {
		v1 = atomic_cmpxchg(a, v, v + add);
		if (likely(v1 == v))
			return v;
	}

	return v;
}

#endif /* __BUS1_UTIL_H */
