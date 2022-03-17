/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2022, Khamba Staring <qdk@quickdekay.net>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <fuse_opt.h>
#include <fuse_lowlevel.h>

#include "srfs_fuse.h"
#include "srfs_client.h"

static void sigint(int signal);
_Noreturn static void srfs_usage(void);
static int srfs_getattr(const char *path, struct stat *st);
static int srfs_readdir(const char *path, void *buffer,
			fuse_fill_dir_t filler, off_t offset,
			struct fuse_file_info *fi);
static int srfs_read(const char *path, char *buffer, size_t size,
		     off_t offset, struct fuse_file_info *fi);

/*static const struct fuse_opt opts[] = {
	FUSE_OPT_END
};*/

static struct fuse_operations fops = {
	.getattr = srfs_getattr,
	.readdir = srfs_readdir,
	.read = srfs_read
};

static struct fuse *fuse = NULL;
static struct fuse_chan *chan = NULL;
static char *serverpath = NULL;
static char *mountpoint = NULL;

static void
sigint(int signal)
{
	fuse_unmount(mountpoint, chan);
	fuse_destroy(fuse);

	exit(0);
}

_Noreturn static void
srfs_usage(void)
{
	printf("Usage: srfs [server:/share] [local mountpoint]\n\n");

	exit(1);
}

static int
srfs_getattr(const char *path, struct stat *st)
{
	return (0);
}

static int
srfs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
	     off_t offset, struct fuse_file_info *fi)
{
	return (0);
}

static int
srfs_read(const char *path, char *buffer, size_t size, off_t offset,
	  struct fuse_file_info *fi)
{
	return (0);
}

static int
srfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	switch (key) {
	case FUSE_OPT_KEY_OPT:
		if (strcmp(arg, "-h") == 0)
			srfs_usage();
		break;
	case FUSE_OPT_KEY_NONOPT:
		if (!serverpath && strchr(arg, ':')) {
			serverpath = strdup(arg);
			return (0);
		}
		if (serverpath && !mountpoint) {
			mountpoint = strdup(arg);
			return (0);
		}
		break;
	}

	return (1);
}

static void
srfs_handle_fuse_event(void)
{
}

static int
srfs_fuse_loop(void)
{
	struct fuse_session *ses;
	struct pollfd pollfds[2];
	int n;

	pollfds[0].fd = fuse_chan_fd(chan);
	pollfds[0].events = POLLIN;

	ses = fuse_get_session(fuse);
	while (!fuse_session_exited(ses)) {
		if ((n = poll(pollfds, 1, 1000)) > 0) {
			if (pollfds[0].revents & POLLIN)
				srfs_handle_fuse_event();
		}
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	if (fuse_opt_parse(&args, NULL, NULL, srfs_opt_proc) == -1)
		return (1);

	if (!serverpath || !mountpoint)
		srfs_usage();

	srfs_client_init();
	if (!srfs_connect(serverpath))
		srfs_usage();

	if (!(chan = fuse_mount(mountpoint, &args)))
		srfs_usage();

	if (!(fuse = fuse_new(chan, &args, &fops,
			      sizeof(struct fuse_operations), NULL))) {
		fuse_unmount(mountpoint, chan);
		return (1);
	}

	signal(SIGINT, sigint);

	srfs_fuse_loop();

	fuse_unmount(mountpoint, chan);
	fuse_destroy(fuse);

	return (1);
}
