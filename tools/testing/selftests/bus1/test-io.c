/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include "test.h"

static int client_send(struct bus1_client *client, uint64_t *destinations,
		       size_t n_destinations, void *data, size_t len)
{
	struct iovec vec = {
		.iov_base = data,
		.iov_len = len,
	};
	struct bus1_cmd_send send = {
		.ptr_destinations = (uintptr_t)destinations,
		.n_destinations = n_destinations,
		.ptr_vecs = (uintptr_t)&vec,
		.n_vecs = 1,
	};

	return bus1_client_send(client, &send);
}

static int client_recv(struct bus1_client *client,
		       const void **datap,
		       size_t *lenp)
{
	struct bus1_cmd_recv recv = {};
	int r;

	assert(datap);
	assert(lenp);

	r = bus1_client_recv(client, &recv);
	if (r < 0)
		return r;

	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.n_dropped == 0);

	*datap = bus1_client_slice_from_offset(client, recv.data.offset);
	*lenp = recv.data.n_bytes;

	return 0;
}

static int client_slice_release(struct bus1_client *client, void *slice)
{
	return bus1_client_slice_release(client,
				bus1_client_slice_to_offset(client, slice));
}

static void test_basic(void)
{
	struct bus1_client *parent, *child1, *child2;
	uint64_t node, aux, parent_handle, child_handles[2];
	struct bus1_cmd_send send;
	struct bus1_cmd_recv recv;
	char *payload = "WOOFWOOF";
	char *reply_payload;
	size_t reply_len;
	int r;

	/* create parent */
	r = bus1_client_new_from_path(&parent, test_path);
	assert(r >= 0);

	r = bus1_client_mmap(parent);
	assert(r >= 0);

	/* create first child */
	r = bus1_client_new_from_path(&child1, test_path);
	assert(r >= 0);

	node = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	parent_handle = BUS1_HANDLE_INVALID;
	r = bus1_client_handle_transfer(parent, child1, &node, &parent_handle);
	assert(r >= 0);

	r = bus1_client_mmap(child1);
	assert(r >= 0);

	/* allocate and send node as auxiliary data to parent */
	aux = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	send = (struct bus1_cmd_send) {
		.ptr_destinations = (unsigned long)&parent_handle,
		.n_destinations = 1,
		.ptr_handles = (unsigned long)&aux,
		.n_handles = 1,
	};
	r = bus1_client_send(child1, &send);
	assert(r >= 0);
	assert(!(aux & BUS1_NODE_FLAG_ALLOCATE));
	assert(aux & BUS1_NODE_FLAG_MANAGED);

	recv = (struct bus1_cmd_recv){};
	r = bus1_client_recv(parent, &recv);
	assert(r >= 0);
	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.n_dropped == 0);
	assert(recv.data.n_bytes == 0);
	assert(recv.data.n_fds == 0);
	assert(recv.data.n_handles == 1);

	child_handles[0] = *(uint64_t*) bus1_client_slice_from_offset(parent,
							recv.data.offset);

	r = bus1_client_slice_release(parent, recv.data.offset);
	assert(r >= 0);

	/* create second child */
	r = bus1_client_new_from_path(&child2, test_path);
	assert(r >= 0);

	node = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	parent_handle = BUS1_HANDLE_INVALID;
	r = bus1_client_handle_transfer(parent, child2, &node, &parent_handle);
	assert(r >= 0);

	r = bus1_client_mmap(child2);
	assert(r >= 0);

	/* allocate and send node as auxiliary data to parent */
	aux = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	send = (struct bus1_cmd_send) {
		.ptr_destinations = (unsigned long)&parent_handle,
		.n_destinations = 1,
		.ptr_handles = (unsigned long)&aux,
		.n_handles = 1,
	};
	r = bus1_client_send(child2, &send);
	assert(r >= 0);
	assert(!(aux & BUS1_NODE_FLAG_ALLOCATE));
	assert(aux & BUS1_NODE_FLAG_MANAGED);

	recv = (struct bus1_cmd_recv){};
	r = bus1_client_recv(parent, &recv);
	assert(r >= 0);
	assert(recv.type == BUS1_MSG_DATA);
	assert(recv.n_dropped == 0);
	assert(recv.data.n_bytes == 0);
	assert(recv.data.n_fds == 0);
	assert(recv.data.n_handles == 1);

	child_handles[1] = *(uint64_t*) bus1_client_slice_from_offset(parent,
							recv.data.offset);

	r = bus1_client_slice_release(parent, recv.data.offset);
	assert(r >= 0);

	/* multicast */
	r = client_send(parent, child_handles, 2, payload, strlen(payload) + 1);
	assert(r >= 0);

	r = client_recv(child1, (const void**)&reply_payload, &reply_len);
	assert(r >= 0);

	assert(reply_len == strlen(payload) + 1);
	assert(memcmp(payload, reply_payload, strlen(payload) + 1) == 0);

	r = client_slice_release(child1, reply_payload);
	assert(r >= 0);

	r = client_recv(child2, (const void**)&reply_payload, &reply_len);
	assert(r >= 0);

	assert(reply_len == strlen(payload) + 1);
	assert(memcmp(payload, reply_payload, strlen(payload) + 1) == 0);

	r = client_slice_release(child2, reply_payload);
	assert(r >= 0);

	/* cleanup */
	parent = bus1_client_free(parent);
	child1 = bus1_client_free(child1);
	child2 = bus1_client_free(child2);
}

static inline uint64_t nsec_from_clock(clockid_t clock)
{
	struct timespec ts;
	int r;

	r = clock_gettime(clock, &ts);
	assert(r >= 0);
	return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

static void test_one(struct bus1_client *parent,
		     struct bus1_client **children,
		     uint64_t *child_handles,
		     unsigned int n_destinations,
		     char *payload,
		     size_t n_bytes)
{
	char *reply_payload;
	size_t reply_len;
	unsigned int i;
	int r;

	/* send */
	r = client_send(parent, child_handles, n_destinations, payload, n_bytes);
	assert(r >= 0);

	/* receive */
	for (i = 0; i < n_destinations; i++) {
		r = client_recv(children[i],
				(const void**)&reply_payload,
				&reply_len);
		assert(r >= 0);

		r = client_slice_release(children[i], reply_payload);
		assert(r >= 0);
	}
}

static uint64_t test_iterate(unsigned int iterations,
			     unsigned int n_destinations,
			     size_t n_bytes)
{
	struct bus1_client *parent, *children[n_destinations];
	uint64_t child_handles[n_destinations];
	char payload[n_bytes];
	unsigned int i;
	uint64_t node, time_start, time_end;
	int r;

	/* create parent */
	r = bus1_client_new_from_path(&parent, test_path);
	assert(r >= 0);

	r = bus1_client_mmap(parent);
	assert(r >= 0);

	/* create children */
	for (i = 0; i < n_destinations; i++) {
		uint64_t parent_handle, aux;
		struct bus1_cmd_send send;
		struct bus1_cmd_recv recv;

		node = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
		parent_handle = BUS1_HANDLE_INVALID;
		r = bus1_client_new_from_path(children + i, test_path);
		assert(r >= 0);

		r = bus1_client_handle_transfer(parent, children[i],
					      &node, &parent_handle);
		assert(r >= 0);

		r = bus1_client_mmap(children[i]);
		assert(r >= 0);

		/* allocate and send node as auxiliary data to parent */
		aux = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
		send = (struct bus1_cmd_send) {
			.ptr_destinations = (unsigned long)&parent_handle,
			.n_destinations = 1,
			.ptr_handles = (unsigned long)&aux,
			.n_handles = 1,
		};
		r = bus1_client_send(children[i], &send);
		assert(r >= 0);
		assert(!(aux & BUS1_NODE_FLAG_ALLOCATE));
		assert(aux & BUS1_NODE_FLAG_MANAGED);

		recv = (struct bus1_cmd_recv){};
		r = bus1_client_recv(parent, &recv);
		assert(r >= 0);
		assert(recv.type == BUS1_MSG_DATA);
		assert(recv.n_dropped == 0);
		assert(recv.data.n_bytes == 0);
		assert(recv.data.n_fds == 0);
		assert(recv.data.n_handles == 1);

		child_handles[i] = *(uint64_t*) bus1_client_slice_from_offset(parent,
								recv.data.offset);

		r = bus1_client_slice_release(parent, recv.data.offset);
		assert(r >= 0);
	}

	/* caches */
	test_one(parent, children, child_handles, n_destinations, payload, n_bytes);

	time_start = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);
	for (i = 0; i < iterations; i++)
		test_one(parent, children, child_handles, n_destinations, payload, n_bytes);
	time_end = nsec_from_clock(CLOCK_THREAD_CPUTIME_ID);

	/* cleanup */
	parent = bus1_client_free(parent);

	for (i = 0; i < n_destinations; i++)
		children[i] = bus1_client_free(children[i]);

	return (time_end - time_start) / iterations;
}

int test_io(void)
{
	unsigned long base;

	test_basic();

	base = test_iterate(1000000, 0, 1024);

	fprintf(stderr, "it took %lu ns for no destinations\n", base);
	fprintf(stderr,
		"it took %lu ns + %lu ns for one destination without payload\n",
		base, test_iterate(100000, 1, 0) - base);
	fprintf(stderr, "it took %lu ns + %lu ns for one destination\n", base,
		test_iterate(100000, 1, 1024) - base);

	for (unsigned int i = 1; i < 9; ++i) {
		unsigned int dests = 1UL << i;

		fprintf(stderr, "it took %lu ns + %lu ns per destination for %u destinations\n",
			base, (test_iterate(100000 >> i, dests, 1024) - base) / dests, dests);
	}

	fprintf(stderr, "\n\n");

	return TEST_OK;
}
