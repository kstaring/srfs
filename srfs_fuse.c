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
#include <unistd.h>
#include <sys/un.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fuse_opt.h>
#include <fuse_lowlevel.h>

#include "srfs_pki.h"
#include "srfs_fuse.h"
#include "srfs_sock.h"
#include "srfs_client.h"
#include "srfs_usrgrp.h"

#define SRFS_AUTH_ERR_INPUT "Illegal input"
#define SRFS_AUTH_ERR_FAILED "Login failed"
#define SRFS_AUTH_ERR_ALREADY "User already logged in"
#define SRFS_AUTH_OK "User logged in"

static void sigint(int signal);
static int srfs_usage(void);

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
static int srfs_fuse_rename(const char *src, const char *dst);
static int srfs_fuse_utimens(const char *path, const struct timespec tv[2]);

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
	.rename = srfs_fuse_rename,
	.utimens = srfs_fuse_utimens
};

static struct fuse *fuse = NULL;
static struct fuse_chan *chan = NULL;
static struct fuse_session *sess = NULL;
static char *serverpath = NULL;
static char *mountpoint = NULL;
static int auth_fd = -1;

static void
sigint(int signal)
{
	fuse_unmount(mountpoint, chan);
	fuse_destroy(fuse);
	unmount(mountpoint, 0);

	exit(0);
}

static int
srfs_usage(void)
{
	printf("Usage: srfs [server:/share] [local mountpoint]\n\n");

	return (1);
}

inline static void
srfs_fuse_setusrctx(void)
{
	struct fuse_context *ctx;

	ctx = fuse_get_context();

	srfs_set_usrctx(ctx->uid, ctx->gid);

	if (ctx->uid == 0)
		return;

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
	mode_t m;

	srfs_fuse_setusrctx();

	errno = 0;
	if ((list = srfs_client_opendir((char *)path, offset))) {
		while ((item = srfs_client_readdir(list))) {
			m = DTTOIF(item->d_type);
			st.st_mode = DTTOIF(m);
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
		rs = MIN(srfs_maxpacketsize(), size);
		if (!(r = srfs_client_read((char *)path, offset, rs, buf)))
			return (-errno);

		offset += r;
		buf += r;
	}

	return (sz);
}

static int
srfs_fuse_write(const char *path, const char *buf, size_t sz,
		off_t offset, struct fuse_file_info *fi)
{
	size_t size;
	int w, ws;

	srfs_fuse_setusrctx();

	for (size = sz; size > 0; size -= w) {
		ws = MIN(srfs_maxpacketsize(), size);
		w = srfs_client_write((char *)path, offset, ws, (char *)buf);

		if (w != ws)
			return (-errno);

		offset += w;
		buf += w;
	}

	return (sz);
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
srfs_fuse_rename(const char *src, const char *dst)
{
	srfs_fuse_setusrctx();
	if (!srfs_client_rename((char *)src, (char *)dst))
		return (-errno);

	return (0);
}

static int
srfs_fuse_utimens(const char *path, const struct timespec tv[2])
{
	srfs_fuse_setusrctx();
	if (!srfs_client_utimens((char *)path, (struct timespec *)tv, 0))
		return (-errno);

	return (0);
}

static int
srfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	switch (key) {
	case FUSE_OPT_KEY_OPT:
		if (strcmp(arg, "-h") == 0)
			return srfs_usage();
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

static void
srfs_handle_auth(void)
{
	char *user, *pass, *ptr;
	struct sockaddr_un un;
#ifdef linux
	struct ucred ucred;
#else
	uid_t uid;
	gid_t gid;
#endif
	char buf[1024];
	socklen_t len;
	size_t rd;
	int fd;

	len = sizeof(struct sockaddr_un);
	if ((fd = accept(auth_fd, (struct sockaddr *)&un, &len)) == -1) {
		close(fd);
		return;
	}

#ifdef linux
	len = sizeof(struct ucred);
	bzero(&ucred, len);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
		close(fd);
		return;
	}

	uid = ucred.uid;
#else
	if (getpeereid(fd, &uid, &gid) == -1) {
		close(fd);
		return;
	}
#endif
	if (!uid) {
		close(fd);
		return;
	}

	if (srfs_uid_authenticated(uid)) {
		write(fd, SRFS_AUTH_ERR_ALREADY, strlen(SRFS_AUTH_ERR_ALREADY));
		close(fd);
		return;
	}

	// TODO should be handled async since one client can connect() and
	// not send data, hanging the whole process and mount
	if ((rd = read(fd, buf, 1024)) < 2) {
		close(fd);
		return;
	}
	buf[rd] = '\0';

	for (user = ptr = buf; *ptr && ptr - buf < rd; ptr++) { }
	if (ptr - buf == rd) {
		write(fd, SRFS_AUTH_ERR_INPUT, strlen(SRFS_AUTH_ERR_INPUT));
		close(fd);
		return;
	}
	pass = ptr + 1;

	if (!srfs_client_user_login_pwd(uid, user, pass)) {
		write(fd, SRFS_AUTH_ERR_FAILED, strlen(SRFS_AUTH_ERR_FAILED));
		close(fd);
		return;
	}

	write(fd, SRFS_AUTH_OK, strlen(SRFS_AUTH_OK));

	close(fd);
}

static int
srfs_fuse_loop(void)
{
	struct pollfd pollfds[3];
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
		pollfds[1].fd = auth_fd;
		pollfds[1].events = POLLIN;

		if ((n = poll(pollfds, 2, 1000)) > 0) {
			if (pollfds[0].revents & POLLIN) {
				if (!fuse_event_handle(&connbuf, ch))
					break;
			}
			if (pollfds[1].revents)
				srfs_handle_auth();
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

	if (!srfs_client_connect(server, path))
		err(errno, "Couldn't connect to server %s", server);

	return (1);
}

static void
srfs_auth_socket_open(char *server, char *mountpoint)
{
	struct sockaddr_un un;
	socklen_t len;
	size_t n;

	len = sizeof(struct sockaddr_un);
	bzero(&un, len);
	un.sun_family = AF_UNIX;
	n = snprintf(un.sun_path, SUNPATHLEN - 1, "/var/run/srfs-auth%s.sock",
		     mountpoint);
	if (n >= SUNPATHLEN)
		err(ENAMETOOLONG, "Couldn't open auth socket for %s", server);

	for (int i = 18; un.sun_path[i]; i++)
		if (un.sun_path[i] == '/')
			un.sun_path[i] = '-';

	if ((auth_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(errno, "Couldn't create auth socket fd");

	unlink(un.sun_path);
	if (bind(auth_fd, (struct sockaddr *)&un, len) == -1)
		err(errno, "Couldn't bind auth socket %s", un.sun_path);
	chmod(un.sun_path, 0666);

	if (listen(auth_fd, 5) == -1)
		err(errno, "Couldn't listen on auth socket %s", un.sun_path);
}

int
main(int argc, char *argv[])
{
	int mountmode = 0;
	char **nargv;
	int nargc;

	nargc = argc;
	nargv = argv;

	// TODO a bit sloppy
	if (strstr(argv[0], "mount_srfs") || strstr(argv[0], "mount.srfs")) {
		nargc += 2;
		nargv = malloc(sizeof(char *) * (argc + 3));
		bcopy(argv, nargv, sizeof(char *) * argc);
		nargv[argc] = "-o";
		nargv[argc + 1] = "allow_other";
		nargv[argc + 2] = NULL;
		mountmode = 1;
	}

	struct fuse_args args = FUSE_ARGS_INIT(nargc, nargv);
	if (fuse_opt_parse(&args, NULL, NULL, srfs_opt_proc) == -1)
		return (1);

	if (!serverpath || !mountpoint)
		return srfs_usage();

	if (!srfs_sock_client_init())
		return (1);

	srfs_client_init();
	srfs_load_hostkeys();

	srfs_auth_socket_open(serverpath, mountpoint);

	if (!srfs_connect(serverpath))
		return srfs_usage();

	if (!(chan = fuse_mount(mountpoint, &args)))
		return srfs_usage();

	if (!(fuse = fuse_new(chan, &args, &fops,
			      sizeof(struct fuse_operations), NULL))) {
		fuse_unmount(mountpoint, chan);
		return (1);
	}

	sess = fuse_get_session(fuse);

	signal(SIGINT, sigint);
	signal(SIGPIPE, SIG_IGN);

	if (mountmode)
		daemon(0, 0);

	srfs_fuse_loop();

	fuse_unmount(mountpoint, chan);
	fuse_destroy(fuse);

	return (1);
}
