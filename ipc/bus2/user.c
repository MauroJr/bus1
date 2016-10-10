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
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include "user.h"

static DEFINE_MUTEX(bus1_user_lock);
static DEFINE_IDR(bus1_user_idr);

static unsigned int bus1_user_max_slices = 16384;
static unsigned int bus1_user_max_handles = 65536;
static unsigned int bus1_user_max_inflight_bytes = 16 * 1024 * 1024;
static unsigned int bus1_user_max_inflight_fds = 4096;

module_param_named(user_slices_max, bus1_user_max_slices,
		   uint, 0644);
module_param_named(user_handles_max, bus1_user_max_handles,
		   uint, 0644);
module_param_named(user_inflight_bytes_max, bus1_user_max_inflight_bytes,
		   uint, 0644);
module_param_named(user_inflight_fds_max, bus1_user_max_inflight_fds,
		   uint, 0644);
MODULE_PARM_DESC(user_max_slices,
		 "Max number of slices for each user.");
MODULE_PARM_DESC(user_max_handles,
		 "Max number of handles for each user.");
MODULE_PARM_DESC(user_max_inflight_bytes,
		 "Max number of inflight bytes for each user.");
MODULE_PARM_DESC(user_max_inflight_fds,
		 "Max number of inflight fds for each user.");

/**
 * bus1_user_modexit() - clean up global resources of user accounting
 *
 * This function cleans up any remaining global resources that were allocated
 * by the user accounting helpers. The caller must make sure that no user
 * object is referenced anymore, before calling this. This function just clears
 * caches and verifies nothing is leaked.
 *
 * This is meant to be called on module-exit.
 */
void bus1_user_modexit(void)
{
	WARN_ON(!idr_is_empty(&bus1_user_idr));
	idr_destroy(&bus1_user_idr);
	idr_init(&bus1_user_idr);
}

/**
 * bus1_user_limits_init() - initialize resource limit counter
 * @limits:		object to initialize
 * @source:		source to initialize from, or NULL
 *
 * This initializes the resource-limit counter @limit. The initial limits are
 * taken from @source, if given. If NULL, the global default limits are taken.
 */
void bus1_user_limits_init(struct bus1_user_limits *limits,
			   struct bus1_user *source)
{
	if (source) {
		limits->max_slices = source->limits.max_slices;
		limits->max_handles = source->limits.max_handles;
		limits->max_inflight_bytes = source->limits.max_inflight_bytes;
		limits->max_inflight_fds = source->limits.max_inflight_fds;
	} else {
		limits->max_slices = bus1_user_max_slices;
		limits->max_handles = bus1_user_max_handles;
		limits->max_inflight_bytes = bus1_user_max_inflight_bytes;
		limits->max_inflight_fds = bus1_user_max_inflight_fds;
	}

	atomic_set(&limits->n_slices, limits->max_slices);
	atomic_set(&limits->n_handles, limits->max_handles);
	atomic_set(&limits->n_inflight_bytes, limits->max_inflight_bytes);
	atomic_set(&limits->n_inflight_fds, limits->max_inflight_fds);
}

/**
 * bus1_user_limits_deinit() - deinitialize source limit counter
 * @limits:		object to deinitialize
 *
 * This should be called on destruction of @limits. It verifies the correctness
 * of the limits and emits warnings if something went wrong.
 */
void bus1_user_limits_deinit(struct bus1_user_limits *limits)
{
	WARN_ON(atomic_read(&limits->n_slices) !=
		limits->max_slices);
	WARN_ON(atomic_read(&limits->n_handles) !=
		limits->max_handles);
	WARN_ON(atomic_read(&limits->n_inflight_bytes) !=
		limits->max_inflight_bytes);
	WARN_ON(atomic_read(&limits->n_inflight_fds) !=
		limits->max_inflight_fds);
}

static struct bus1_user *bus1_user_new(void)
{
	struct bus1_user *user;

	user = kmalloc(sizeof(*user), GFP_KERNEL);
	if (!user)
		return ERR_PTR(-ENOMEM);

	kref_init(&user->ref);
	user->uid = INVALID_UID;
	bus1_user_limits_init(&user->limits, NULL);

	return user;
}

static void bus1_user_free(struct kref *ref)
{
	struct bus1_user *user = container_of(ref, struct bus1_user, ref);

	lockdep_assert_held(&bus1_user_lock);

	if (likely(uid_valid(user->uid)))
		idr_remove(&bus1_user_idr, __kuid_val(user->uid));
	bus1_user_limits_deinit(&user->limits);
	kfree_rcu(user, rcu);
}

/**
 * bus1_user_ref_by_uid() - get a user object for a uid
 * @uid:		uid of the user
 *
 * Find and return the user object for the uid if it exists, otherwise create
 * it first.
 *
 * Return: A user object for the given uid, ERR_PTR on failure.
 */
struct bus1_user *bus1_user_ref_by_uid(kuid_t uid)
{
	struct bus1_user *user;
	int r;

	if (WARN_ON(!uid_valid(uid)))
		return ERR_PTR(-ENOTRECOVERABLE);

	/* fast-path: acquire reference via rcu */
	rcu_read_lock();
	user = idr_find(&bus1_user_idr, __kuid_val(uid));
	if (user && !kref_get_unless_zero(&user->ref))
		user = NULL;
	rcu_read_unlock();
	if (user)
		return user;

	/* slow-path: try again with IDR locked */
	mutex_lock(&bus1_user_lock);
	user = idr_find(&bus1_user_idr, __kuid_val(uid));
	if (likely(!bus1_user_ref(user))) {
		user = bus1_user_new();
		if (!IS_ERR(user)) {
			user->uid = uid;
			r = idr_alloc(&bus1_user_idr, user, __kuid_val(uid),
				      __kuid_val(uid) + 1, GFP_KERNEL);
			if (r < 0) {
				user->uid = INVALID_UID; /* couldn't insert */
				kref_put(&user->ref, bus1_user_free);
			}
		}
	}
	mutex_unlock(&bus1_user_lock);

	return user;
}

/**
 * bus1_user_ref() - acquire reference
 * @user:	user to acquire, or NULL
 *
 * Acquire an additional reference to a user-object. The caller must already
 * own a reference.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @user is returned.
 */
struct bus1_user *bus1_user_ref(struct bus1_user *user)
{
	if (user)
		kref_get(&user->ref);
	return user;
}

/**
 * bus1_user_unref() - release reference
 * @user:	user to release, or NULL
 *
 * Release a reference to a user-object.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
struct bus1_user *bus1_user_unref(struct bus1_user *user)
{
	if (user) {
		if (kref_put_mutex(&user->ref, bus1_user_free, &bus1_user_lock))
			mutex_unlock(&bus1_user_lock);
	}

	return NULL;
}

/**
 * bus1_user_charge() - charge a user resource
 * @global:		global resource to charge on
 * @local:		local resource to charge on
 * @charge:		charge to apply
 *
 * This charges @charge on two resource counters. Only if both charges apply,
 * this returns success.
 *
 * Note that negative charges always apply. Only positive charges might be
 * refused if exceeding the limit.
 *
 * Return: True if @charge was applied, otherwise false.
 */
bool bus1_user_charge(atomic_t *global, atomic_t *local, int charge)
{
	int v;

	if (charge > 0) {
		v = bus1_atomic_add_if_ge(global, charge, -charge);
		if (v < charge)
			return false;

		v = bus1_atomic_add_if_ge(local, charge, -charge);
		if (v < charge) {
			atomic_add(charge, global);
			return false;
		}
	} else if (charge < 0) {
		atomic_sub(charge, local);
		atomic_sub(charge, global);
	}

	return true;
}
