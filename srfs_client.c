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

#include <err.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/endian.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "srfs_pki.h"
#include "srfs_sock.h"
#include "srfs_iobuf.h"
#include "srfs_client.h"
#include "srfs_usrgrp.h"
#include "srfs_config.h"
#include "srfs_protocol.h"

typedef struct srfs_dirlist {
	char path[SRFS_MAXPATHLEN + 1];
	char *listbuf;
	char *ptr;
	size_t count;
	size_t idx;
	size_t offset;
	size_t bufsize;
} srfs_dirlist_t;

typedef struct srfs_usercontext {
	uid_t uid;
	gid_t gid;
	char usrname[SRFS_MAXLOGNAMELEN];
	char grpname[SRFS_MAXGRPNAMELEN];
} srfs_usercontext_t;

static srfs_usercontext_t usrctx = { 0 };
static srfs_id_t serial;

static int srfs_return_errno(int err);
static void srfs_requesthdr_fill(srfs_iobuf_t *r, srfs_opcode_t opcode);
static int srfs_execute_rpc(srfs_iobuf_t *req, srfs_iobuf_t *resp);

static srfs_iobuf_t *req = NULL;
static srfs_iobuf_t *resp = NULL;

static char server_host[MAXHOSTNAMELEN + 1];
static char server_path[MAXPATHLEN + 1];

static int reconnect_delay = 0;

void
srfs_client_init(void)
{
	req = srfs_iobuf_alloc(SRFS_IOBUFSZ);
	resp = srfs_iobuf_alloc(SRFS_IOBUFSZ);

	srfs_usrgrp_init();
}

size_t
srfs_maxpacketsize(void)
{
	return (resp->bufsize - sizeof(srfs_response_t));
}

static int
srfs_return_errno(int err)
{
	errno = err;

	return (0);
}

static void
srfs_requesthdr_fill(srfs_iobuf_t *r, srfs_opcode_t opcode)
{
	srfs_request_t *req;

	req = SRFS_IOBUF_REQUEST(r);
	req->r_serial = htobe64(serial);
	req->r_opcode = htons(opcode);
	req->r_size = 0;
	r->ptr += sizeof(srfs_request_t);
}

static int
srfs_request_fill_path(srfs_iobuf_t *req, srfs_opcode_t opcode, char *path)
{
	size_t len;

	if ((len = strlen(path)) > SRFS_MAXPATHLEN)
		return (srfs_return_errno(ENAMETOOLONG));

	SRFS_IOBUF_RESET(req);
	srfs_requesthdr_fill(req, opcode);
	srfs_iobuf_addstr(req, usrctx.usrname);
	srfs_iobuf_addstr(req, usrctx.grpname);
	srfs_iobuf_addstr(req, path);

	return (1);
}

static void
srfs_request_finalize(srfs_iobuf_t *req)
{
	srfs_request_t *r;
	srfs_bufsz_t size;

	r = SRFS_IOBUF_REQUEST(req);

	size = SRFS_IOBUF_SIZE(req) - sizeof(srfs_request_t);
	r->r_size = htobe32(size);
	req->size = SRFS_IOBUF_SIZE(req);
}

int
srfs_client_connect(char *server, char *path)
{
	if (strlen(server) > MAXHOSTNAMELEN) {
		errno = EINVAL;
		return (0);
	}
	if (strlen(path) > MAXPATHLEN) {
		errno = ENAMETOOLONG;
		return (0);
	}

	if (server_host != server)
		strcpy(server_host, server);
	if (server_path != path)
		strcpy(server_path, path);

	if (!srfs_sock_connect(server))
		return (0);

	if (!srfs_client_host_login()) {
		errno = EACCES;
		printf("Couldn't login to %s with client host key",
		       server_host);
		return (0);
	}

	if (!srfs_client_mount(path)) {
		printf("Couldn't mount %s:%s", server_host, server_path);
		return (0);
	}

	reconnect_delay = 0;

	return (1);
}

static void
srfs_reconnect(void)
{
	srfs_flush_auth();

	if (!reconnect_delay)
		syslog(LOG_DAEMON | LOG_INFO, "%s:%s connection lost",
		       server_host, server_path);

	sleep(reconnect_delay);

	if (srfs_client_connect(server_host, server_path)) {
		syslog(LOG_DAEMON | LOG_INFO, "%s:%s reconnected",
		       server_host, server_path);
	} else {
		syslog(LOG_DAEMON | LOG_INFO, "%s:%s reconnect failed",
		       server_host, server_path);
		if (reconnect_delay < 20)
			reconnect_delay++;
	}
}

static int
srfs_request_send(srfs_iobuf_t *req)
{
	return (srfs_sock_write_sync(req->buf, SRFS_IOBUF_SIZE(req)));
}

static void
srfs_client_set_errno(srfs_errno_t err)
{
	switch (err) {
	case SRFS_ENOENT:	errno = ENOENT; break;
	case SRFS_EIO:		errno = EIO; break;
	case SRFS_EBADF:	errno = EBADF; break;
	case SRFS_EPERM:	errno = EPERM; break;
	case SRFS_EACCESS:	errno = EACCES; break;
	case SRFS_EXIST:	errno = EEXIST; break;
	case SRFS_ENOTDIR:	errno = ENOTDIR; break;
	case SRFS_EISDIR:	errno = EISDIR; break;
	case SRFS_EINVAL:	errno = EINVAL; break;
	case SRFS_EINFILE:	errno = ENFILE; break;
	case SRFS_ETXTBSY:	errno = ETXTBSY; break;
	case SRFS_EFBIG:	errno = EFBIG; break;
	case SRFS_ENOSPC:	errno = ENOSPC; break;
	case SRFS_ESEEK:	errno = ESPIPE; break;
	case SRFS_EROFS:	errno = EROFS; break;
	case SRFS_EAGAIN:	errno = EAGAIN; break;
	case SRFS_ENOTSUP:	errno = ENOTSUP; break;
	case SRFS_ENAMETOOLONG: errno = ENAMETOOLONG; break;
	case SRFS_ENEEDAUTH:	errno = EACCES; break;
	default:		errno = EIO; break;
	}
}

void
srfs_set_usrctx(uid_t uid, gid_t gid)
{
	char *usr, *grp;

	if (uid == 0) {
		uid = srfs_uidbyname("nobody");
		gid = srfs_uidbyname("nogroup");
	}

	if (uid == usrctx.uid && gid == usrctx.gid)
		return;

	usr = srfs_rmtnamebyuid(uid);
	//usr = srfs_usrconv(uid);
	grp = srfs_namebygid(gid);

	usrctx.uid = uid;
	usrctx.gid = gid;
	strcpy(usrctx.usrname, usr);
	strcpy(usrctx.grpname, grp);
}

static void
srfs_client_user_from_config(char *home, char *subdir, char *user)
{
	char path[MAXPATHLEN + 1];
	char srvcontext[256];
	char *ptr, *idx;
	char buf[1024];
	FILE *f;

	user[0] = '\0';
	if (snprintf(path, MAXPATHLEN + 1, "%s/%s/config",
		       srfs_homebyuid(usrctx.uid), subdir) >= MAXPATHLEN + 1)
		return;

	if (!(f = fopen(path, "r")))
		return;

	srvcontext[0] = '\0';
	while (fgets(buf, 1024, f)) {
		buf[1023] = '\0';
		ptr = buf;
		for (ptr = buf; *ptr == '\t' || *ptr == ' '; ptr++) { }
		if (strncmp(ptr, "Host ", 5) == 0) {
			if ((idx = index(ptr, '\n')))
				*idx = '\0';
			strlcpy(srvcontext, ptr + 5, 255);
		}

		if (strncmp(ptr, "User ", 5) == 0) {
			if (strcmp(srvcontext, server_host) != 0)
				continue;
			ptr += 5;
			if ((idx = index(ptr, '\n')))
				*idx = '\0';
			strcpy(user, ptr);
			break;
		}
	}

	fclose(f);
}

static int
srfs_client_user_login_path(char *subdir, uint8_t auth_type)
{
	char path[MAXPATHLEN + 1];
	char user[SRFS_MAXLOGNAMELEN];
	size_t sz, len;
	struct stat st;
	char *home;
	char *sign;

	home = srfs_homebyuid(usrctx.uid);

	srfs_client_user_from_config(home, subdir, user);
	len = snprintf(path, MAXPATHLEN + 1, "%s/%s/id_rsa", home, subdir);
	if (len >= MAXPATHLEN + 1)
		return (0);

	if (stat(path, &st) == -1)
		return (0);

	if (st.st_uid != usrctx.uid)
		return (0);

	if (!srfs_rsa_sign_path(path, sign_challenge(), SRFS_CHALLENGE_SZ,
				&sign, &sz))
		return (0);

	SRFS_IOBUF_RESET(req);
	srfs_requesthdr_fill(req, SRFS_LOGIN);
	srfs_iobuf_add8(req, auth_type);
	srfs_iobuf_addstr(req, user[0] ? user : usrctx.usrname);
	if (!srfs_iobuf_addptr(req, sign, sz)) {
		free(sign);
		return (srfs_return_errno(EIO));
	}
	free(sign);

	if (!srfs_execute_rpc(req, resp))
		return (0);

	sfrs_set_authenticated(usrctx.usrname, user[0] ? user : NULL);

	return (1);
}

int
srfs_client_user_login_pwd(uid_t uid, char *rmtuser, char *pass)
{
	char *name;

	if (!(name = srfs_namebyuid(uid))) {
		errno = ENOENT;
		return (0);
	}
	if (rmtuser && strcmp(name, rmtuser) != 0)
		name = rmtuser;

	SRFS_IOBUF_RESET(req);
	srfs_requesthdr_fill(req, SRFS_LOGIN);
	srfs_iobuf_add8(req, SRFS_AUTH_PWD);
	srfs_iobuf_addstr(req, name);
	srfs_iobuf_addstr(req, pass);

	if (!srfs_execute_rpc(req, resp))
		return (0);

	sfrs_set_authenticated(srfs_namebyuid(uid), rmtuser);

	return (1);
}

int
srfs_client_user_login(void)
{
	if (srfs_client_user_login_path(".srfs", SRFS_AUTH_SRFS))
		return (1);

	return (srfs_client_user_login_path(".ssh", SRFS_AUTH_SSH));
}

srfs_id_t
srfs_serial(void)
{
	srfs_id_t res;

	res = serial;
	serial++;

	return (res);
}

static int
srfs_client_read_response(srfs_iobuf_t *resp)
{
	srfs_response_t *r;

	SRFS_IOBUF_RESET(resp);
	if (srfs_sock_read_sync(resp->buf, sizeof(srfs_response_t)) == -1)
		return (-1);

	r = SRFS_IOBUF_RESPONSE(resp);
	r->r_errno = ntohs(r->r_errno);
	r->r_size = be32toh(r->r_size);
	if (r->r_errno != SRFS_OK) {
		srfs_client_set_errno(r->r_errno);
		return (0);
	}

	if (r->r_size > resp->size - sizeof(srfs_response_t))
		return (srfs_return_errno(EMSGSIZE));

	if (r->r_size) {
		resp->ptr = resp->buf + sizeof(srfs_response_t);
		if (!srfs_sock_read_sync(resp->ptr, r->r_size))
			return (0);

		resp->size = sizeof(srfs_response_t) + r->r_size;
	} else {
		resp->size = 0;
	}

	return (1);
}

static int
srfs_execute_rpc(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	int res;

	srfs_request_finalize(req);

	for (;;) {
		while ((res = srfs_request_send(req)) == -1)
			srfs_reconnect();

		if (!res)
			return (0);

		if ((res = srfs_client_read_response(resp)) != -1)
			break;

		srfs_reconnect();
	}

	return (res);
}

int
srfs_request_path(char *path, srfs_opcode_t opcode,
		  srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	if (!srfs_request_fill_path(req, opcode, path))
		return (0);

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_host_login(void)
{
	char *sign;
	size_t sz;

	if (!srfs_host_privkey())
		return (0);

	if (!srfs_rsa_sign(srfs_host_privkey(), sign_challenge(),
			   SRFS_CHALLENGE_SZ, &sign, &sz)) {
		printf("Couldn't sign the server challenge\n");
		return (0);
	}

	SRFS_IOBUF_RESET(req);
	srfs_requesthdr_fill(req, SRFS_LOGIN);

	srfs_iobuf_add8(req, SRFS_AUTH_HOST);
	if (!srfs_iobuf_addptr(req, sign, sz)) {
		free(sign);
		return (srfs_return_errno(EIO));
	}

	free(sign);

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_mount(char *share)
{
	size_t len;

	if ((len = strlen(share)) > SRFS_MAXNAMLEN)
		return (srfs_return_errno(ENAMETOOLONG));

	SRFS_IOBUF_RESET(req);
	srfs_requesthdr_fill(req, SRFS_MOUNT);
	srfs_iobuf_addstr(req, share);

	if (!srfs_execute_rpc(req, resp))
		return (0);

	if (SRFS_IOBUF_LEFT(resp) != 0)
		return (srfs_return_errno(EINVAL));

	return (1);
}

int
srfs_client_statvfs(char *path, struct statvfs *vfs)
{
	srfs_statvfs_t *svfs;

	if (!srfs_request_path(path, SRFS_STATVFS, req, resp))
		return (0);

	if (!(svfs = (srfs_statvfs_t *)srfs_iobuf_getptr(resp, sizeof(srfs_statvfs_t))))
		return (srfs_return_errno(EIO));

	vfs->f_bavail = be64toh(svfs->f_bavail);
	vfs->f_bfree = be64toh(svfs->f_bfree);
	vfs->f_blocks = be64toh(svfs->f_blocks);
	vfs->f_favail = be64toh(svfs->f_favail);
	vfs->f_ffree = be64toh(svfs->f_ffree);
	vfs->f_files = be64toh(svfs->f_files);
	vfs->f_bsize = be64toh(svfs->f_bsize);
	vfs->f_flag = be64toh(svfs->f_flag);
	vfs->f_frsize = be64toh(svfs->f_frsize);
	vfs->f_fsid = be64toh(svfs->f_fsid);
	vfs->f_namemax = be64toh(svfs->f_namemax);

	return (1);
}

int
srfs_client_stat(char *path, struct stat *st)
{
	char *usrname, *grpname;
	srfs_response_t *r;
	srfs_stat_t *rst;
	uid_t uid;
	gid_t gid;
	int len;

	if (!srfs_request_path(path, SRFS_STAT, req, resp))
		return (0);

	r = SRFS_IOBUF_RESPONSE(resp);
	len = sizeof(srfs_stat_t) + 4;
	if (r->r_size < len)
		return (srfs_return_errno(EIO));

	if (!(rst = (srfs_stat_t *)srfs_iobuf_getptr(resp, sizeof(srfs_stat_t))))
		return (srfs_return_errno(EIO));

	if (!(usrname = srfs_iobuf_getstr(resp)))
		return (srfs_return_errno(EIO));
	if (!(grpname = srfs_iobuf_getstr(resp)))
		return (srfs_return_errno(EIO));

	uid = srfs_uidbyname(usrname);
	gid = srfs_gidbyname(grpname);

	st->st_ino = be64toh(rst->st_ino);
	st->st_size = be64toh(rst->st_size);
	st->st_blocks = be64toh(rst->st_blocks);
	st->st_atim.tv_sec = be64toh(rst->st_atim.tv_sec);
	st->st_atim.tv_nsec = be32toh(rst->st_atim.tv_nsec);
	st->st_mtim.tv_sec = be64toh(rst->st_mtim.tv_sec);
	st->st_mtim.tv_nsec = be32toh(rst->st_mtim.tv_nsec);
	st->st_ctim.tv_sec = be64toh(rst->st_ctim.tv_sec);
	st->st_ctim.tv_nsec = be32toh(rst->st_ctim.tv_nsec);
	st->st_blksize = be32toh(rst->st_blksize);
	st->st_mode = be32toh(rst->st_mode);
	st->st_dev = ntohs(rst->st_dev);
	st->st_nlink = ntohs(rst->st_nlink);
	st->st_flags = ntohs(rst->st_flags);
	st->st_uid = uid;
	st->st_gid = gid;

	return (1);
}

static int
srfs_client_dirlist_fill(srfs_dirlist_t *dirlist, off_t offset)
{
	size_t size;
	char *ptr;

	dirlist->ptr = dirlist->listbuf;
	dirlist->count = 0;
	dirlist->idx = 0;
	dirlist->offset = offset;

	if (!srfs_request_fill_path(req, SRFS_READDIR, dirlist->path))
		return (0);
	srfs_iobuf_add64(req, offset);
	srfs_iobuf_add32(req, dirlist->bufsize);

	if (!srfs_execute_rpc(req, resp))
		return (0);

	size = SRFS_IOBUF_LEFT(resp);
	if (size < 2) {
		errno = 0;
		return (1);
	}

	if (size > dirlist->bufsize) {
		errno = EIO;
		return (0);
	}

	if (!size)
		return (1);

	bcopy(resp->ptr, dirlist->listbuf, size);
	dirlist->listbuf[dirlist->bufsize - 1] = '\0';
	dirlist->count = 0;
	for (ptr = dirlist->listbuf; ptr - dirlist->listbuf < size - 2;) {
		ptr++; // d_type
		ptr = index(ptr, '\0') + 1;
		dirlist->count++;
	}

	return (1);
}

srfs_dirlist_t *
srfs_client_opendir(char *path, off_t offset)
{
	srfs_dirlist_t *res;

	res = malloc(sizeof(srfs_dirlist_t));
	res->bufsize = resp->bufsize - sizeof(srfs_response_t);
	res->listbuf = malloc(resp->bufsize);
	strlcpy(res->path, path, SRFS_MAXPATHLEN);

	if (!srfs_client_dirlist_fill(res, offset))
		return (NULL);

	return (res);
}

srfs_dirent_t *
srfs_client_readdir(srfs_dirlist_t *dirlist)
{
	srfs_dirent_t *res;
	off_t offset;

	if (!dirlist)
		return (NULL);

	if (dirlist->count == dirlist->idx) {
		offset = dirlist->offset + dirlist->count;
		if (!srfs_client_dirlist_fill(dirlist, offset))
			return (NULL);
	}

	if (!dirlist->count)
		return (NULL);

	res = (srfs_dirent_t *)dirlist->ptr;

	dirlist->ptr = index(dirlist->ptr + 1, '\0') + 1;
	dirlist->idx++;

	return (res);
}

void
srfs_client_closedir(srfs_dirlist_t *dirlist)
{
	if (!dirlist)
		return;

	free(dirlist->listbuf);
	free(dirlist);
}

int
srfs_client_read(char *path, off_t offset, size_t size, char *buf)
{
	if (!srfs_request_fill_path(req, SRFS_READ, path))
		return (0);
	srfs_iobuf_add64(req, offset);
	srfs_iobuf_add64(req, size);

	if (!srfs_execute_rpc(req, resp))
		return (0);

	bcopy(resp->ptr, buf, SRFS_IOBUF_LEFT(resp));

	return (SRFS_IOBUF_LEFT(resp));
}

int
srfs_client_write(char *path, off_t offset, size_t size, char *buf)
{
	if (!srfs_request_fill_path(req, SRFS_WRITE, path))
		return (0);
	srfs_iobuf_add64(req, offset);

	if (!srfs_iobuf_addptr(req, buf, size))
		return (srfs_return_errno(EIO));

	if (!srfs_execute_rpc(req, resp))
		return (0);

	return (size);
}

int
srfs_client_access(char *path, int mode)
{
	if (!srfs_request_fill_path(req, SRFS_ACCESS, path))
		return (0);
	if (!srfs_iobuf_add32(req, mode))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_create(char *path, int mode)
{
	if (!srfs_request_fill_path(req, SRFS_CREATE, path))
		return (0);
	if (!srfs_iobuf_add32(req, mode))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_unlink(char *path)
{
	return (srfs_request_path(path, SRFS_UNLINK, req, resp));
}

int
srfs_client_mkdir(char *path, mode_t mode)
{
	if (!srfs_request_fill_path(req, SRFS_MKDIR, path))
		return (0);
	if (!srfs_iobuf_add16(req, mode))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_rmdir(char *path)
{
	return (srfs_request_path(path, SRFS_RMDIR, req, resp));
}

int
srfs_client_chown(char *path, uid_t uid, gid_t gid)
{
	char *usr, *grp;

	usr = srfs_namebyuid(uid);
	grp = srfs_namebyuid(gid);

	if (!srfs_request_fill_path(req, SRFS_CHOWN, path))
		return (0);
	if (!srfs_iobuf_addstr(req, usr))
		return (srfs_return_errno(EIO));
	if (!srfs_iobuf_addstr(req, grp))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_chmod(char *path, mode_t mode)
{
	if (!srfs_request_fill_path(req, SRFS_CHMOD, path))
		return (0);
	if (!srfs_iobuf_add16(req, mode))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_link(char *pointee, char *pointer)
{
	if (!srfs_request_fill_path(req, SRFS_LINK, pointee))
		return (0);
	if (!srfs_iobuf_addstr(req, pointer))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_symlink(char *pointee, char *pointer)
{
	if (!srfs_request_fill_path(req, SRFS_SYMLINK, pointee))
		return (0);
	if (!srfs_iobuf_addstr(req, pointer))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_rename(char *src, char *dst)
{
	if (!srfs_request_fill_path(req, SRFS_RENAME, src))
		return (0);
	if (!srfs_iobuf_addstr(req, dst))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}

int
srfs_client_readlink(char *path, char *buf, size_t size)
{
	size_t sz;
	char *lnk;

	if (!srfs_request_path(path, SRFS_READLINK, req, resp))
		return (0);

	if (!(lnk = srfs_iobuf_getstr(resp)))
		return (srfs_return_errno(EIO));

	sz = MIN(strlen(lnk), size);

	strlcpy(buf, lnk, sz);

	return (sz);
}

int
srfs_client_utimens(char *path, struct timespec times[2], int flag)
{
	struct srfs_timespec stm[2];

	if (!srfs_request_fill_path(req, SRFS_UTIMENS, path))
		return (0);

	stm[0].tv_sec = htobe64(times[0].tv_sec);
	stm[0].tv_nsec = htobe32(times[0].tv_nsec);
	stm[1].tv_sec = htobe64(times[1].tv_sec);
	stm[1].tv_nsec = htobe32(times[1].tv_nsec);

	if (!srfs_iobuf_addptr(req, (char *)&stm, sizeof(stm)))
		return (srfs_return_errno(EIO));

	if (!srfs_iobuf_add32(req, flag))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(req, resp));
}
