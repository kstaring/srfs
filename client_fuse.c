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

#define FUSE_USE_VERSION 25

#include <stdio.h>
#include <stdlib.h>
#include <fuse.h>
#include <fuse_opt.h>
#include "client_fuse.h"
#include "srfs_client.h"

static void usage(char *prog);
static int srfs_getattr(const char *path, struct stat *st);
static int srfs_readdir(const char *path, void *buffer,
			fuse_fill_dir_t filler, off_t offset,
			struct fuse_file_info *fi);
static int srfs_read(const char *path, char *buffer, size_t size,
		     off_t offset, struct fuse_file_info *fi);

static struct fuse_operations fops = {
	.getattr = srfs_getattr,
	.readdir = srfs_readdir,
	.read = srfs_read
};

static void
usage(char *prog)
{
	printf("Usage: %s [server:/share]\n\n", prog);
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

int
main(int argc, char *argv[])
{
	char *srv_path;

	if (argv > 0) {
		srv_path = argv[1];
		argc--;
		argv++;
	} else {
		usage(argv[0]);
		exit(1);
	}

	srfs_connect(srv_path);

	return (fuse_main(argc, argv, &fops));
}
