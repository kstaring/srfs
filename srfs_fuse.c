/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2022, Khamba Staring <staring@blingbsd.org>
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

#include <err.h>
#include <fuse.h>
#include <poll.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <fuse_opt.h>
#include <fuse_lowlevel.h>

#include "srfs_pki.h"
#include "srfs_fuse.h"
#include "srfs_sock.h"
#include "srfs_client.h"
#include "srfs_usrgrp.h"

static void sigint(int signal);
_Noreturn static void srfs_usage(void);

static int srfs_fuse_statfs(const char *path, struct statvfs *vfs);
static int srfs_fuse_getattr(const char *path, struct stat *st);
static int srfs_fuse_opendir(const char *path, struct fuse_file_info *fi);
static int srfs_fuse_releasedir(const char *path, struct fuse_file_info *fi);
static int srfs_fuse_readdir(const char *path, void *buffer,
			     fuse_fill_dir_t filler, off_t offset,
			     struct fuse_file_info *fi);
static int srfs_fuse_read(const char *path, char *buffer, size_t size,
			  off_t offset, struct fuse_file_info *fi);
static int srfs_fuse_write(const char *path, const char *buffer, size_t size,
			   off_t offset, struct fuse_file_info *fi);
static int srfs_fuse_create(const char *path, mode_t mode,
			    struct fuse_file_info *fi);
static int srfs_fuse_truncate(const char *path, off_t offset);
static int srfs_fuse_access(const char *path, int mode);
static int srfs_fuse_unlink(const char *path);
static int srfs_fuse_mkdir(const char *path, mode_t mode);
static int srfs_fuse_rmdir(const char *path);
static int srfs_fuse_chmod(const char *path, mode_t mode);
static int srfs_fuse_chown(const char *path, uid_t uid, gid_t gid);
static int srfs_fuse_link(const char *to, const char *from);
static int srfs_fuse_symlink(const char *to, const char *from);
static int srfs_fuse_readlink(const char *path, char *buf, size_t size);

/*static const struct fuse_opt opts[] = {
	FUSE_OPT_END
};*/

static struct fuse_operations fops = {
	.statfs = srfs_fuse_statfs,
	.getattr = srfs_fuse_getattr,
	.opendir = srfs_fuse_opendir,
	.releasedir = srfs_fuse_releasedir,
	.readdir = srfs_fuse_readdir,
	.read = srfs_fuse_read,
	.write = srfs_fuse_write,
	.create = srfs_fuse_create,
	.truncate = srfs_fuse_truncate,
	.access = srfs_fuse_access,
	.unlink = srfs_fuse_unlink,
	.mkdir = srfs_fuse_mkdir,
	.rmdir = srfs_fuse_rmdir,
	.chown = srfs_fuse_chown,
	.chmod = srfs_fuse_chmod,
	.link = srfs_fuse_link,
	.symlink = srfs_fuse_symlink,
	.readlink = srfs_fuse_readlink,
};

static struct fuse *fuse = NULL;
static struct fuse_chan *chan = NULL;
static struct fuse_session *sess = NULL;
static char *serverpath = NULL;
static char *mountpoint = NULL;

static void
sigint(int signal)
{
	fuse_unmount(mountpoint, chan);
	fuse_destroy(fuse);
	unmount(mountpoint, 0);

	exit(0);
}

_Noreturn static void
srfs_usage(void)
{
	printf("Usage: srfs [server:/share] [local mountpoint]\n\n");

	exit(1);
}

inline static void
srfs_fuse_setusrctx(void)
{
	struct fuse_context *ctx;

	ctx = fuse_get_context();

	srfs_set_usrctx(ctx->uid, ctx->gid);

	if (!srfs_uid_authenticated(ctx->uid))
		srfs_client_user_login();
}

static int
srfs_fuse_statfs(const char *path, struct statvfs *vfs)
{
	srfs_fuse_setusrctx();
	return (srfs_client_statvfs((char *)path, vfs) ? 0 : -errno);
}

static int
srfs_fuse_getattr(const char *path, struct stat *st)
{
	srfs_fuse_setusrctx();
	return (srfs_client_stat((char *)path, st) ? 0 : -errno);
}

static int
srfs_fuse_opendir(const char *path, struct fuse_file_info *fi)
{
	return (0);
}

static int
srfs_fuse_releasedir(const char *path, struct fuse_file_info *fi)
{
	return (0);
}

static int
srfs_fuse_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
		  off_t offset, struct fuse_file_info *fi)
{
	srfs_dirlist_t *list;
	srfs_dirent_t *item;
	struct stat st = { 0 };

	srfs_fuse_setusrctx();

	errno = 0;
	if ((list = srfs_client_opendir((char *)path, offset))) {
		while ((item = srfs_client_readdir(list))) {
			st.st_mode = DTTOIF(item->d_type);
			filler(buffer, item->d_name, &st, 0);
			offset++;
		}
	}
	srfs_client_closedir(list);

	return (0);
}

static int
srfs_fuse_read(const char *path, char *buf, size_t sz, off_t offset,
	       struct fuse_file_info *fi)
{
	size_t size;
	int r, rs;

	srfs_fuse_setusrctx();

	for (size = sz; size > 0; size -= r) {
		rs = MIN(1024, size);
		if (!(r = srfs_client_read((char *)path, offset, rs, buf)))
			return (-errno);

		if (r < rs)
			return (-EOF);

		offset += r;
		buf += r;
	}

	return (sz);
}

static int
srfs_fuse_write(const char *path, const char *buffer, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	int res;

	srfs_fuse_setusrctx();

	if (!(res = srfs_client_write((char *)path, offset, size,
				      (char *)buffer)))
		return (-errno);

	return (res);
}

static int
srfs_fuse_access(const char *path, int mode)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_access((char *)path, mode))
		return (-errno);

	return (0);
}

static int
srfs_fuse_unlink(const char *path)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_unlink((char *)path))
		return (-errno);

	return (0);
}

static int
srfs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_create((char *)path, mode))
		return (-errno);

	return (0);
}

static int
srfs_fuse_truncate(const char *path, off_t offset)
{
	char buf[1];

	srfs_fuse_setusrctx();
	return (srfs_fuse_write(path, buf, 0, offset, NULL));
}

static int
srfs_fuse_mkdir(const char *path, mode_t mode)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_mkdir((char *)path, mode))
		return (-errno);

	return (0);
}

static int
srfs_fuse_rmdir(const char *path)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_rmdir((char *)path))
		return (-errno);

	return (0);
}

static int
srfs_fuse_chown(const char *path, uid_t uid, gid_t gid)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_chown((char *)path, uid, gid))
		return (-errno);

	return (0);
}

static int
srfs_fuse_chmod(const char *path, mode_t mode)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_chmod((char *)path, mode))
		return (-errno);

	return (0);
}

static int
srfs_fuse_link(const char *to, const char *from)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_link((char *)to, (char *)from))
		return (-errno);

	return (0);
}

static int
srfs_fuse_symlink(const char *to, const char *from)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_symlink((char *)to, (char *)from))
		return (-errno);

	return (0);
}

static int
srfs_fuse_readlink(const char *path, char *buf, size_t size)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_readlink((char *)path, buf, size))
		return (-errno);

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

static int
fuse_event_handle(struct fuse_buf *connbuf, struct fuse_chan *ch)
{
	struct fuse_chan *tmp;
	int res;

	tmp = ch;
	res = fuse_session_receive_buf(sess, connbuf, &tmp);

	if (res == -EINTR)
		return (1);
	if (res <= 0)
		return (0);

	fuse_session_process_buf(sess, connbuf, tmp);

	return (1);
}

static int
srfs_fuse_loop(void)
{
	struct pollfd pollfds[2];
	struct fuse_chan *ch;
	size_t cbufsize;
	char *cbuf;
	int n;

	ch = fuse_session_next_chan(sess, NULL);
	cbufsize = fuse_chan_bufsize(ch);
	cbuf = malloc(cbufsize);

	while (!fuse_session_exited(sess)) {
		struct fuse_buf connbuf = {
			.mem = cbuf,
			.size = cbufsize
		};

		pollfds[0].fd = fuse_chan_fd(chan);
		pollfds[0].events = POLLIN;

		if ((n = poll(pollfds, 1, 1000)) > 0) {
			if (pollfds[0].revents & POLLIN) {
				if (!fuse_event_handle(&connbuf, ch))
					break;
			}
		}
	}

	free(cbuf);
	fuse_session_reset(sess);

	return (1);
}

int
srfs_connect(char *server_path)
{
	char *server;
	char *path;
	char *sep;

	if (!(sep = index(server_path, '/')))
		return (0);
	if (sep == server_path)
		return (0);
	sep--;
	if (*sep != ':')
		return (0);

	*sep = '\0';

	server = server_path;
	path = sep + 1;

	if (!srfs_sock_connect(server))
		err(errno, "Couldn't connect to server %s", server);

	if (!srfs_client_host_login())
		printf("Couldn't login with client host key");

	if (!srfs_client_mount(path))
		err(errno, "Couldn't mount");

	return (1);
}

int
main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	if (fuse_opt_parse(&args, NULL, NULL, srfs_opt_proc) == -1)
		return (1);

	if (!serverpath || !mountpoint)
		srfs_usage();

	if (!srfs_sock_client_init())
		return (1);

	srfs_load_hostkeys();

	if (!srfs_connect(serverpath))
		srfs_usage();

	if (!(chan = fuse_mount(mountpoint, &args)))
		srfs_usage();

	if (!(fuse = fuse_new(chan, &args, &fops,
			      sizeof(struct fuse_operations), NULL))) {
		fuse_unmount(mountpoint, chan);
		return (1);
	}

	sess = fuse_get_session(fuse);

	signal(SIGINT, sigint);

	srfs_fuse_loop();

	fuse_unmount(mountpoint, chan);
	fuse_destroy(fuse);

	return (1);
}
