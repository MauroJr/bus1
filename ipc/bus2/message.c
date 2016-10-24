/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <uapi/linux/bus1.h>
#include "message.h"
#include "node.h"
#include "util/queue.h"

/**
 * bus1_message_new() - XXX
 */
struct bus1_message *bus1_message_new(struct bus1_handle *dst)
{
	struct bus1_message *m;

	m = kmalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	kref_init(&m->ref);
	bus1_queue_node_init(&m->qnode, BUS1_MSG_DATA);
	m->dst = bus1_handle_ref(dst);

	return m;
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

	bus1_handle_unref(m->dst);
	bus1_queue_node_deinit(&m->qnode);
	kfree_rcu(m, qnode.rcu);
}
