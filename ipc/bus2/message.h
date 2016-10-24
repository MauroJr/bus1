#ifndef __BUS1_MESSAGE_H
#define __BUS1_MESSAGE_H

/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

/**
 * DOC: Messages
 *
 * XXX
 */

#include <linux/kernel.h>
#include <linux/kref.h>
#include "util/queue.h"

struct bus1_handle;

/**
 * struct bus1_message - data messages
 * @ref:		reference counter
 * @qnode:		embedded queue node
 * @dst:		destination handle
 */
struct bus1_message {
	struct kref ref;
	struct bus1_queue_node qnode;
	struct bus1_handle *dst;
};

struct bus1_message *bus1_message_new(struct bus1_handle *dst);
void bus1_message_free(struct kref *k);

/**
 * bus1_message_ref() - acquire object reference
 * @m:			message to operate on, or NULL
 *
 * This acquires a single reference to @m. The caller must already hold a
 * reference when calling this.
 *
 * If @m is NULL, this is a no-op.
 *
 * Return: @m is returned.
 */
static inline struct bus1_message *bus1_message_ref(struct bus1_message *m)
{
	if (m)
		kref_get(&m->ref);
	return m;
}

/**
 * bus1_message_unref() - release object reference
 * @m:			message to operate on, or NULL
 *
 * This releases a single object reference to @m. If the reference counter
 * drops to 0, the message is destroyed.
 *
 * If @m is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline struct bus1_message *bus1_message_unref(struct bus1_message *m)
{
	if (m)
		kref_put(&m->ref, bus1_message_free);
	return NULL;
}

#endif /* __BUS1_MESSAGE_H */
