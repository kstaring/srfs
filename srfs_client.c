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
#include <sys/endian.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
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
	char listbuf[SRFS_READDIR_BUFSZ];
	char *ptr;
	size_t count;
	size_t idx;
	size_t offset;
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

	SRFS_IOBUF_INIT(req);
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
	uint16_t size;

	r = SRFS_IOBUF_REQUEST(req);

	size = SRFS_IOBUF_SIZE(req) - sizeof(srfs_request_t);
	r->r_size = htons(size);
	req->size = SRFS_IOBUF_SIZE(req);
}

static int
srfs_request_send(srfs_iobuf_t *req)
{
	srfs_request_finalize(req);

	if (!srfs_sock_write_sync(req->buf, SRFS_IOBUF_SIZE(req)))
		return (0);

	return (1);
}

static void
srfs_client_set_errno(srfs_errno_t err)
{
	switch (err) {
	case SRFS_ENOENT:	errno = ENOENT; break;
	case SRFS_EIO:		errno = EIO; break;
	case SRFS_EBADF:	errno = EBADF; break;
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

	usr = srfs_namebyuid(uid);
	//usr = srfs_usrconv(uid);
	grp = srfs_namebygid(gid);

	usrctx.uid = uid;
	usrctx.gid = gid;
	strcpy(usrctx.usrname, usr);
	strcpy(usrctx.grpname, grp);
}

int
srfs_client_user_login(void)
{
	char ppath[MAXPATHLEN + 1];
	srfs_iobuf_t req, resp;
	size_t len;
	char *sign;
	size_t sz;

	len = snprintf(ppath, MAXPATHLEN + 1, "%s/.srfs/id_rsa.key",
		       srfs_homebyuid(usrctx.uid));
	if (len == MAXPATHLEN)
		return (0);

	if (!srfs_rsa_sign_path(ppath, sign_challenge(), SRFS_CHALLENGE_SZ,
				&sign, &sz))
		return (0);

	SRFS_IOBUF_INIT(&req);
	srfs_requesthdr_fill(&req, SRFS_LOGIN);
	srfs_iobuf_add8(&req, SRFS_AUTH_SRFS);
	srfs_iobuf_addstr(&req, usrctx.usrname);
	if (!srfs_iobuf_addptr(&req, sign, sz)) {
		free(sign);
		return (srfs_return_errno(EIO));
	}
	free(sign);

	if (!srfs_execute_rpc(&req, &resp))
		return (0);

	sfrs_set_authenticated(usrctx.usrname);

	return (1);
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

	SRFS_IOBUF_INIT(resp);
	if (!srfs_sock_read_sync(resp->buf, sizeof(srfs_response_t)))
		return (0);

	r = SRFS_IOBUF_RESPONSE(resp);
	r->r_errno = ntohs(r->r_errno);
	r->r_size = ntohs(r->r_size);
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
	if (!srfs_request_send(req))
		return (0);

	if (!srfs_client_read_response(resp))
		return (0);

	return (1);
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
	srfs_iobuf_t req, resp;
	char *sign;
	size_t sz;

	if (!srfs_host_privkey())
		return (0);

	if (!srfs_rsa_sign(srfs_host_privkey(), sign_challenge(),
			   SRFS_CHALLENGE_SZ, &sign, &sz)) {
		printf("Couldn't sign the server challenge\n");
		return (0);
	}

	SRFS_IOBUF_INIT(&req);
	srfs_requesthdr_fill(&req, SRFS_LOGIN);

	srfs_iobuf_add8(&req, SRFS_AUTH_HOST);
	if (!srfs_iobuf_addptr(&req, sign, sz)) {
		free(sign);
		return (srfs_return_errno(EIO));
	}

	free(sign);

	return (srfs_execute_rpc(&req, &resp));
}

int
srfs_client_mount(char *share)
{
	srfs_iobuf_t req, resp;
	size_t len;

	if ((len = strlen(share)) > SRFS_MAXNAMLEN)
		return (srfs_return_errno(ENAMETOOLONG));

	SRFS_IOBUF_INIT(&req);
	srfs_requesthdr_fill(&req, SRFS_MOUNT);
	srfs_iobuf_addstr(&req, share);

	if (!srfs_execute_rpc(&req, &resp))
		return (0);

	if (SRFS_IOBUF_LEFT(&resp) != 0)
		return (srfs_return_errno(EINVAL));

	return (1);
}

int
srfs_client_statvfs(char *path, struct statvfs *vfs)
{
	srfs_iobuf_t req, resp;
	srfs_statvfs_t *svfs;

	if (!srfs_request_path(path, SRFS_STATVFS, &req, &resp))
		return (0);

	if (!(svfs = (srfs_statvfs_t *)srfs_iobuf_getptr(&resp, sizeof(srfs_statvfs_t))))
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
	srfs_iobuf_t req, resp;
	srfs_response_t *r;
	srfs_stat_t *rst;
	char *usrgrpbuf;
	srfs_size_t len;
	uid_t uid;
	gid_t gid;

	if (!srfs_request_path(path, SRFS_STAT, &req, &resp))
		return (0);

	r = SRFS_IOBUF_RESPONSE(&resp);
	len = sizeof(srfs_stat_t) + 4;
	if (r->r_size < len)
		return (srfs_return_errno(EIO));

	if (!(rst = (srfs_stat_t *)srfs_iobuf_getptr(&resp, sizeof(srfs_stat_t))))
		return (srfs_return_errno(EIO));

	len = ntohs(rst->st_usrgrpsz);
	if (len < 4 || len > SRFS_MAXLOGNAMELEN + SRFS_MAXGRPNAMELEN)
		return (srfs_return_errno(EIO));

	if (!(usrgrpbuf = srfs_iobuf_getptr(&resp, len)))
		return (srfs_return_errno(EIO));

	usrname = usrgrpbuf;
	if (!(grpname = index(usrgrpbuf, '\0')))
		return (0);
	grpname++;
	if (!strlen(usrname) || !strlen(grpname))
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
	st->st_mode = ntohs(rst->st_mode);
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
	srfs_iobuf_t req, resp;
	size_t size;
	char *ptr;

	dirlist->ptr = dirlist->listbuf;
	dirlist->count = 0;
	dirlist->idx = 0;
	dirlist->offset = offset;

	if (!srfs_request_fill_path(&req, SRFS_READDIR, dirlist->path))
		return (0);
	srfs_iobuf_add64(&req, offset);
	srfs_iobuf_add16(&req, SRFS_READDIR_BUFSZ);

	if (!srfs_execute_rpc(&req, &resp))
		return (0);

	size = SRFS_IOBUF_LEFT(&resp);
	if (size < 2) {
		errno = 0;
		return (1);
	}

	if (size > SRFS_READDIR_BUFSZ) {
		errno = EIO;
		return (0);
	}

	if (!size)
		return (1);

	bcopy(resp.ptr, dirlist->listbuf, size);
	dirlist->listbuf[SRFS_READDIR_BUFSZ - 1] = '\0';
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
	strncpy(res->path, path, SRFS_MAXPATHLEN);
	res->path[SRFS_MAXPATHLEN] = '\0';

	if (!srfs_client_dirlist_fill(res, offset))
		return (NULL);

	return (res);
}

srfs_dirent_t *
srfs_client_readdir(srfs_dirlist_t *dirlist)
{
	srfs_dirent_t *res;
	off_t offset;

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
	free(dirlist);
}

int
srfs_client_read(char *path, off_t offset, size_t size, char *buf)
{
	srfs_iobuf_t req, resp;

	if (!srfs_request_fill_path(&req, SRFS_READ, path))
		return (0);
	srfs_iobuf_add64(&req, offset);
	srfs_iobuf_add64(&req, size);

	if (!srfs_execute_rpc(&req, &resp))
		return (0);

	bcopy(resp.ptr, buf, SRFS_IOBUF_LEFT(&resp));

	return (SRFS_IOBUF_LEFT(&resp));
}

int
srfs_client_write(char *path, off_t offset, size_t size, char *buf)
{
	srfs_iobuf_t req, resp;

	if (!srfs_request_fill_path(&req, SRFS_WRITE, path))
		return (0);
	srfs_iobuf_add64(&req, offset);

	if (!srfs_iobuf_addptr(&req, buf, size))
		return (srfs_return_errno(EIO));

	if (!srfs_execute_rpc(&req, &resp))
		return (0);

	return (size);
}

int
srfs_client_access(char *path, int mode)
{
	srfs_iobuf_t req, resp;

	if (!srfs_request_fill_path(&req, SRFS_ACCESS, path))
		return (0);
	if (!srfs_iobuf_add32(&req, mode))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(&req, &resp));
}

int
srfs_client_create(char *path, int mode)
{
	srfs_iobuf_t req, resp;

	if (!srfs_request_fill_path(&req, SRFS_CREATE, path))
		return (0);
	if (!srfs_iobuf_add32(&req, mode))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(&req, &resp));
}

int
srfs_client_unlink(char *path)
{
	srfs_iobuf_t req, resp;

	return (srfs_request_path(path, SRFS_UNLINK, &req, &resp));
}

int
srfs_client_mkdir(char *path, mode_t mode)
{
	srfs_iobuf_t req, resp;

	if (!srfs_request_fill_path(&req, SRFS_MKDIR, path))
		return (0);
	if (!srfs_iobuf_add16(&req, mode))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(&req, &resp));
}

int
srfs_client_rmdir(char *path)
{
	srfs_iobuf_t req, resp;

	return (srfs_request_path(path, SRFS_RMDIR, &req, &resp));
}

int
srfs_client_chown(char *path, uid_t uid, gid_t gid)
{
	srfs_iobuf_t req, resp;
	char *usr, *grp;

	usr = srfs_namebyuid(uid);
	grp = srfs_namebyuid(gid);

	if (!srfs_request_fill_path(&req, SRFS_CHOWN, path))
		return (0);
	if (!srfs_iobuf_addstr(&req, usr))
		return (srfs_return_errno(EIO));
	if (!srfs_iobuf_addstr(&req, grp))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(&req, &resp));
}

int
srfs_client_chmod(char *path, mode_t mode)
{
	srfs_iobuf_t req, resp;

	if (!srfs_request_fill_path(&req, SRFS_CHMOD, path))
		return (0);
	if (!srfs_iobuf_add16(&req, mode))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(&req, &resp));
}

int
srfs_client_link(char *pointee, char *pointer)
{
	srfs_iobuf_t req, resp;

	if (!srfs_request_fill_path(&req, SRFS_LINK, pointee))
		return (0);
	if (!srfs_iobuf_addstr(&req, pointer))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(&req, &resp));
}

int
srfs_client_symlink(char *pointee, char *pointer)
{
	srfs_iobuf_t req, resp;

	if (!srfs_request_fill_path(&req, SRFS_SYMLINK, pointee))
		return (0);
	if (!srfs_iobuf_addstr(&req, pointer))
		return (srfs_return_errno(EIO));

	return (srfs_execute_rpc(&req, &resp));
}

int
srfs_client_readlink(char *path, char *buf, size_t size)
{
	srfs_iobuf_t req, resp;
	size_t sz;
	char *lnk;

	if (!srfs_request_path(path, SRFS_READLINK, &req, &resp))
		return (0);

	if (!(lnk = srfs_iobuf_getstr(&resp)))
		return (srfs_return_errno(EIO));

	sz = MIN(strlen(lnk), size);

	bcopy(lnk, buf, sz);

	return (1);
}
