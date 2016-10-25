/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include "test.h"

/* make sure /dev/busX exists, is a cdev and accessible */
static void test_api_cdev(void)
{
	const uint8_t *map;
	struct stat st;
	size_t n_map;
	int r, fd;

	r = access(test_path, F_OK);
	assert(r >= 0);

	r = stat(test_path, &st);
	assert(r >= 0);
	assert((st.st_mode & S_IFMT) == S_IFCHR);

	r = open(test_path, O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
	assert(r >= 0);
	close(r);

	fd = test_open(&map, &n_map);
	test_close(fd, map, n_map);
}

/* make sure basic connect works */
static void test_api_connect(void)
{
	struct bus1_cmd_peer_reset cmd_reset = {
		.flags			= 0,
		.peer_flags		= -1,
		.max_slices		= -1,
		.max_handles		= -1,
		.max_inflight_bytes	= -1,
		.max_inflight_fds	= -1,
	};
	const uint8_t *map1;
	size_t n_map1;
	int r, fd1;

	/* create @fd1 */

	fd1 = test_open(&map1, &n_map1);

	/* test empty RESET */

	r = bus1_ioctl_peer_reset(fd1, &cmd_reset);
	assert(r >= 0);

	/* test DISCONNECT and verify ESHUTDOWN afterwards */

	r = bus1_ioctl_peer_disconnect(fd1);
	assert(r >= 0);

	r = bus1_ioctl_peer_disconnect(fd1);
	assert(r < 0);
	assert(r == -ESHUTDOWN);

	r = bus1_ioctl_peer_reset(fd1, &cmd_reset);
	assert(r < 0);
	assert(r == -ESHUTDOWN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

/* make sure basic transfer works */
static void test_api_transfer(void)
{
	struct bus1_cmd_handle_transfer cmd_transfer;
	const uint8_t *map1, *map2;
	size_t n_map1, n_map2;
	int r, fd1, fd2;

	/* setup */

	fd1 = test_open(&map1, &n_map1);
	fd2 = test_open(&map2, &n_map2);

	/* import a handle from @fd1 into @fd2 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= 0x100,
		.dst_fd			= fd2,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	assert(cmd_transfer.dst_handle != BUS1_HANDLE_INVALID);
	assert(cmd_transfer.dst_handle & BUS1_HANDLE_FLAG_MANAGED);
	assert(cmd_transfer.dst_handle & BUS1_HANDLE_FLAG_REMOTE);

	/* cleanup */

	test_close(fd2, map2, n_map2);
	test_close(fd1, map1, n_map1);
}

/* test release notification */
static void test_api_notify_release(void)
{
	struct bus1_cmd_handle_transfer cmd_transfer;
	struct bus1_cmd_recv cmd_recv;
	const uint8_t *map1;
	uint64_t id = 0x100;
	size_t n_map1;
	int r, fd1;

	/* setup */

	fd1 = test_open(&map1, &n_map1);

	/* import a handle from @fd1 into @fd2 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= id,
		.dst_fd			= -1,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	assert(cmd_transfer.dst_handle == id);

	/* no message can be queued */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* release handle to trigger release notification */

	r = bus1_ioctl_handle_release(fd1, &id);
	assert(r == 0);

	/* dequeue release notification */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_RELEASE);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == id);

	/* no more messages */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/*
	 * Trigger the same thing again.
	 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= id,
		.dst_fd			= -1,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	assert(cmd_transfer.dst_handle == id);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	r = bus1_ioctl_handle_release(fd1, &id);
	assert(r == 0);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_RELEASE);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == id);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

/* test destroy notification */
static void test_api_notify_destroy(void)
{
	struct bus1_cmd_handle_transfer cmd_transfer;
	struct bus1_cmd_nodes_destroy cmd_destroy;
	struct bus1_cmd_recv cmd_recv;
	uint64_t node = 0x100, handle;
	const uint8_t *map1, *map2;
	size_t n_map1, n_map2;
	int r, fd1, fd2;

	/* setup */

	fd1 = test_open(&map1, &n_map1);
	fd2 = test_open(&map2, &n_map2);

	/* import a handle from @fd1 into @fd2 */

	cmd_transfer = (struct bus1_cmd_handle_transfer){
		.flags			= 0,
		.src_handle		= node,
		.dst_fd			= fd2,
		.dst_handle		= BUS1_HANDLE_INVALID,
	};
	r = bus1_ioctl_handle_transfer(fd1, &cmd_transfer);
	assert(r >= 0);
	handle = cmd_transfer.dst_handle;

	/* both queues must be empty */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map2,
	};
	r = bus1_ioctl_recv(fd2, &cmd_recv);
	assert(r == -EAGAIN);

	/* destroy node and trigger destruction notification */

	cmd_destroy = (struct bus1_cmd_nodes_destroy){
		.flags			= 0,
		.ptr_nodes		= (unsigned long)&node,
		.n_nodes		= 1,
	};
	r = bus1_ioctl_nodes_destroy(fd1, &cmd_destroy);
	assert(r >= 0);

	/* dequeue destruction notification */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_DESTROY);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == node);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd2, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_NODE_DESTROY);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == handle);

	/* cleanup */

	test_close(fd2, map2, n_map2);
	test_close(fd1, map1, n_map1);
}

/* make sure basic unicasts works */
static void test_api_unicast(void)
{
	struct bus1_cmd_send cmd_send;
	struct bus1_cmd_recv cmd_recv;
	const uint8_t *map1;
	uint64_t id = 0x100;
	size_t n_map1;
	int r, fd1;

	/* setup */

	fd1 = test_open(&map1, &n_map1);

	/* send empty message */

	cmd_send = (struct bus1_cmd_send){
		.flags			= 0,
		.ptr_destinations	= (unsigned long)&id,
		.ptr_errors		= 0,
		.n_destinations		= 1,
		.ptr_vecs		= 0,
		.n_vecs			= 0,
		.ptr_handles		= 0,
		.n_handles		= 0,
		.ptr_fds		= 0,
		.n_fds			= 0,
	};
	r = bus1_ioctl_send(fd1, &cmd_send);
	assert(r >= 0);

	/* retrieve empty message */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_DATA);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == id);

	/* queue must be empty now */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

/* make sure basic multicasts works */
static void test_api_multicast(void)
{
	struct bus1_cmd_send cmd_send;
	struct bus1_cmd_recv cmd_recv;
	uint64_t ids[] = { 0x100, 0x200 };
	const uint8_t *map1;
	size_t n_map1;
	int r, fd1;

	/* setup */

	fd1 = test_open(&map1, &n_map1);

	/* send empty multicast */

	cmd_send = (struct bus1_cmd_send){
		.flags			= 0,
		.ptr_destinations	= (unsigned long)ids,
		.ptr_errors		= 0,
		.n_destinations		= sizeof(ids) / sizeof(*ids),
		.ptr_vecs		= 0,
		.n_vecs			= 0,
		.ptr_handles		= 0,
		.n_handles		= 0,
		.ptr_fds		= 0,
		.n_fds			= 0,
	};
	r = bus1_ioctl_send(fd1, &cmd_send);
	assert(r >= 0);

	/* retrieve empty messages */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_DATA);
	assert(cmd_recv.msg.flags == BUS1_MSG_FLAG_CONTINUE);
	assert(cmd_recv.msg.destination == ids[0] ||
	       cmd_recv.msg.destination == ids[1]);

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r >= 0);
	assert(cmd_recv.msg.type == BUS1_MSG_DATA);
	assert(cmd_recv.msg.flags == 0);
	assert(cmd_recv.msg.destination == ids[0] ||
	       cmd_recv.msg.destination == ids[1]);

	/* queue must be empty now */

	cmd_recv = (struct bus1_cmd_recv){
		.flags = 0,
		.max_offset = n_map1,
	};
	r = bus1_ioctl_recv(fd1, &cmd_recv);
	assert(r == -EAGAIN);

	/* cleanup */

	test_close(fd1, map1, n_map1);
}

#if 0
/* make sure basic handle-release/destroy (with notifications) works */
static void test_api_handle(void)
{
	struct bus1_cmd_recv recv;
	struct bus1_peer *c1, *c2;
	uint64_t node, handle;
	struct bus1_cmd_node_destroy destroy = {
		.n_nodes = 1,
	};
	int r;

	/* create two peers and import a handle from one to the other */

	r = bus1_peer_new_from_path(&c1, test_path);
	assert(r >= 0);
	r = bus1_peer_new_from_path(&c2, test_path);
	assert(r >= 0);

	node = BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE;
	r = bus1_peer_handle_transfer(c1, c2, &node, &handle);
	assert(r >= 0);
	assert(node != (BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE));
	assert(handle != BUS1_HANDLE_INVALID);

	/* verify clone-handle has no DESTROY access */

	destroy.ptr_nodes = (uintptr_t)&handle;
	r = bus1_peer_node_destroy(c2, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);

	/* verify that no notification has been queued, yet */

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r == -EAGAIN);
	r = bus1_peer_recv(c2, &recv);
	assert(r == -EAGAIN);

	/* verify clone-handle can release its handle exactly once */

	r = bus1_peer_handle_release(c2, handle);
	assert(r >= 0);
	r = bus1_peer_handle_release(c2, handle);
	assert(r < 0);
	assert(r == -ENXIO);

	/* verify that a release notification was queued */

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_NODE_RELEASE);
	assert(recv.msg.destination == node);

	/* verify that the owner does not have a userref to its handle */

	r = bus1_peer_handle_release(c1, node);
	assert(r < 0);
	assert(r == -ENXIO);

	/* verify that the owner can destroy its handle exactly once */

	destroy.ptr_nodes = (uintptr_t)&node;
	r = bus1_peer_node_destroy(c1, &destroy);
	assert(r >= 0);
	r = bus1_peer_node_destroy(c1, &destroy);
	assert(r < 0);
	assert(r == -ENXIO);

	/* verify that a destruction notification was queued */

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_NODE_DESTROY);
	assert(recv.msg.destination == node);

	/* verify that both queues are empty (no unexpected notifications) */

	recv = (struct bus1_cmd_recv){};
	r = bus1_peer_recv(c1, &recv);
	assert(r == -EAGAIN);
	r = bus1_peer_recv(c2, &recv);
	assert(r == -EAGAIN);

	/* drop peers */

	c2 = bus1_peer_free(c2);
	assert(!c2);

	c1 = bus1_peer_free(c1);
	assert(!c1);
}

/* make sure we can set + get seed */
static void test_api_seed(void)
{
	struct bus1_peer *client;
	char *payload = "WOOF";
	struct iovec vecs[] = {
		{
			.iov_base = payload,
			.iov_len = strlen(payload) + 1,
		},
	};
	uint64_t handles[] = {
		BUS1_NODE_FLAG_MANAGED | BUS1_NODE_FLAG_ALLOCATE,
	};
	struct bus1_cmd_send send = {
		.flags = BUS1_SEND_FLAG_SEED,
		.ptr_vecs = (uintptr_t)vecs,
		.n_vecs = sizeof(vecs) / sizeof(*vecs),
		.ptr_handles = (uintptr_t)handles,
		.n_handles = sizeof(handles) / sizeof(*handles),
	};
	struct bus1_cmd_recv recv = {
		.flags = BUS1_RECV_FLAG_SEED,
	};
	const void *slice;
	uint64_t handle_id;
	int r;

	/* setup default client */

	r = bus1_peer_new_from_path(&client, test_path);
	assert(r >= 0);
	r = bus1_peer_mmap(client);
	assert(r >= 0);

	/* set SEED on @client and verify that nodes were properly created */

	r = bus1_peer_send(client, &send);
	assert(r >= 0);

	assert(handles[0] != 0);
	assert(handles[0] != BUS1_HANDLE_INVALID);
	assert(!(handles[0] & BUS1_NODE_FLAG_ALLOCATE));

	/* verify that we can replace a SEED */

	r = bus1_peer_send(client, &send);
	assert(r >= 0);

	/* retrieve SEED and verify its content */

	r = bus1_peer_recv(client, &recv);
	assert(r >= 0);
	assert(recv.msg.type == BUS1_MSG_DATA);

	slice = bus1_peer_slice_from_offset(client, recv.msg.offset);
	assert(slice);

	assert(recv.msg.n_bytes == strlen(payload) + 1);
	assert(strncmp(slice, payload, recv.msg.n_bytes) == 0);
	handle_id = *(uint64_t *)((uint8_t *)slice + ((recv.msg.n_bytes + 7) & ~(7ULL)));
	assert(handle_id != 0);
	assert(handle_id != BUS1_HANDLE_INVALID);
	assert(!(handle_id & BUS1_NODE_FLAG_ALLOCATE));

	client = bus1_peer_free(client);
	assert(!client);
}
#endif

int main(int argc, char **argv)
{
	int r;

	r = test_parse_argv(argc, argv);
	if (r > 0) {
		test_api_cdev();
		test_api_connect();
		test_api_transfer();
		test_api_notify_release();
		test_api_notify_destroy();
		test_api_unicast();
		test_api_multicast();
	}

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
