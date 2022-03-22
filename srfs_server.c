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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/endian.h>
#include <arpa/inet.h>

#include "srfs_protocol.h"
#include "srfs_exports.h"
#include "srfs_server.h"
#include "srfs_usrgrp.h"
#include "srfs_iobuf.h"
#include "srfs_sock.h"

#define RESPONSE_SIZE(x) sizeof(srfs_response_t) + x

#define SRFS_REPLBUF_SZ 4096
typedef struct srfs_replbuf {
	char buf[SRFS_REPLBUF_SZ];
	srfs_response_t *response;
	char *ptr;
} srfs_replbuf_t;

typedef int (*srfs_server_func_t)(srfs_iobuf_t *req, srfs_iobuf_t *resp);
typedef struct srfs_funcproc {
	srfs_opcode_t opcode;
	srfs_server_func_t func;
} srfs_funcproc_t;

static char *srfs_opcodes[] = {
	"SRFS_MOUNT",
	"SRFS_LOGIN",
	"SRFS_READDIR",
	"SRFS_STAT",
	"SRFS_READ",
	"SRFS_WRITE"
};

static int srfs_not_implemented(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_invalid_opcode(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_mount(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_readdir(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_stat(srfs_iobuf_t *req, srfs_iobuf_t *resp);

static srfs_funcproc_t srfs_funcprocs[] = {
	{ SRFS_MOUNT,		srfs_mount },
	{ SRFS_LOGIN,		srfs_not_implemented },
	{ SRFS_READDIR,		srfs_readdir },
	{ SRFS_STAT,		srfs_stat },
	{ SRFS_READ,		srfs_not_implemented },
	{ SRFS_WRITE,		srfs_not_implemented },
	{ SRFS_ACCESS,		srfs_not_implemented },
	{ SRFS_OPCODE_MAX,	srfs_invalid_opcode }
};

/* TODO only temporary, POC */
static srfs_export_t *exported = NULL;

static int
srfs_localpath(srfs_export_t *export, char *path, char *dstpath)
{
	char rpath[MAXPATHLEN];
	size_t llen, plen;

	llen = strlen(export->localdir);
	plen = strlen(path);
	if (strlen(export->localdir) + strlen(path) > SRFS_MAXPATHLEN) {
		errno = ENAMETOOLONG;
		return (0);
	}
	bcopy(export->localdir, dstpath, llen);
	bcopy(path, dstpath + llen, plen);
	dstpath[llen + plen] = '\0';

	if (!realpath(dstpath, rpath))
		return (0);
	if (strncmp(rpath, export->localdir, llen) != 0) {
		errno = EACCES;
		return (0);
	}

	return (1);
}

static int
srfs_err_response(srfs_iobuf_t *r, srfs_errno_t err)
{
	srfs_response_t *resp;

	resp = SRFS_IOBUF_RESPONSE(r);
	resp->r_errno = err;
	resp->r_size = 0;

	return (1);
}

static int
srfs_errno_response(srfs_iobuf_t *r)
{
	srfs_response_t *resp;
	srfs_errno_t status;

	resp = SRFS_IOBUF_RESPONSE(r);

	switch (errno) {
	case ENOENT:	status = SRFS_ENOENT; break;
	case EIO:	status = SRFS_EIO; break;
	case EBADF:	status = SRFS_EBADF; break;
	case EACCES:	status = SRFS_EACCESS; break;
	case EEXIST:	status = SRFS_EXIST; break;
	case ENOTDIR:	status = SRFS_ENOTDIR; break;
	case EISDIR:	status = SRFS_EISDIR; break;
	case EINVAL:	status = SRFS_EINVAL; break;
	case ENFILE:	status = SRFS_EINFILE; break;
	case ETXTBSY:	status = SRFS_ETXTBSY; break;
	case EFBIG:	status = SRFS_EFBIG; break;
	case ENOSPC:	status = SRFS_ENOSPC; break;
	case ESPIPE:	status = SRFS_ESEEK; break;
	case EROFS:	status = SRFS_EROFS; break;
	case EAGAIN:	status = SRFS_EAGAIN; break;
	case ENOTSUP:	status = SRFS_ENOTSUP; break;
	case ENAMETOOLONG: status = SRFS_ENAMETOOLONG; break;
	default:
		printf("srfs_errno_response: unhandled errno: %d\n", errno);
		status = EIO;
	}

	resp->r_errno = status;
	resp->r_size = 0;

	return (1);
}

static int
srfs_not_implemented(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
printf("not implemented!\n");
	return (srfs_err_response(resp, SRFS_ENOTSUP));
}

static int
srfs_invalid_opcode(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
printf("invalid opcode!\n");
	return (srfs_err_response(resp, SRFS_EINVAL));
}

static int
srfs_mount(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	srfs_export_t *export;
	char *share;

	if (req->size > SRFS_MAXNAMLEN + 1)
		return (srfs_err_response(resp, SRFS_ENAMETOOLONG));

	if (!(share = srfs_iobuf_getstr(req)))
		return (srfs_err_response(resp, SRFS_EIO));

	if (!(export = srfs_export_by_sharename(share)))
		return (srfs_err_response(resp, SRFS_ENOENT));

	exported = export;

	printf("mounted %s\n", export->share);

	return (1);
}

static int
srfs_stat(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	char *usrname, *grpname;
	srfs_stat_t rst;
	struct stat st;
	char *spath;

	if (req->size > SRFS_MAXNAMLEN + 1)
		return (srfs_err_response(resp, SRFS_ENAMETOOLONG));

	if (!(spath = srfs_iobuf_getstr(req)))
		return (srfs_err_response(resp, SRFS_EIO));

	if (!srfs_localpath(exported, spath, path))
		return (srfs_errno_response(resp));

	if (stat(path, &st) != 0)
		return (srfs_errno_response(resp));

	usrname = srfs_namebyuid(st.st_uid);
	grpname = srfs_namebygid(st.st_gid);

	rst.st_ino = htobe64(st.st_ino);
	rst.st_size = htobe64(st.st_size);
	rst.st_blocks = htobe64(st.st_blocks);
	rst.st_atim.tv_sec = htobe64(st.st_atim.tv_sec);
	rst.st_atim.tv_nsec = htobe32(st.st_atim.tv_nsec);
	rst.st_mtim.tv_sec = htobe64(st.st_mtim.tv_sec);
	rst.st_mtim.tv_nsec = htobe32(st.st_mtim.tv_nsec);
	rst.st_ctim.tv_sec = htobe64(st.st_ctim.tv_sec);
	rst.st_ctim.tv_nsec = htobe32(st.st_ctim.tv_nsec);
	rst.st_blksize = htobe32(st.st_blksize);
	rst.st_mode = htons(st.st_mode);
	rst.st_dev = htons(st.st_dev);
	rst.st_nlink = htons(st.st_nlink);
	rst.st_flags = htons(st.st_flags);
	rst.st_usrgrpsz = htons(strlen(usrname) + strlen(grpname) + 2);

	printf("stat(%s): usr=%s grp=%s sz=%ld mode=%d\n", path,
	       usrname, grpname, st.st_size, st.st_mode & 0777);

	if (!srfs_iobuf_addptr(resp, (char *)&rst, sizeof(srfs_stat_t)))
		return (srfs_err_response(resp, SRFS_EIO));
	if (!srfs_iobuf_addstr(resp, usrname))
		return (srfs_err_response(resp, SRFS_EIO));
	if (!srfs_iobuf_addstr(resp, grpname))
		return (srfs_err_response(resp, SRFS_EIO));

	return (1);
}

static int
srfs_readdir(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	srfs_off_t offset, idx;
	srfs_size_t replsize;
	struct dirent *dire;
	srfs_dirent_t rde;
	char *spath;
	size_t len;
	DIR *dirp;

	if (!(spath = srfs_iobuf_getstr(req)))
		return (srfs_err_response(resp, SRFS_EIO));

	if (strlen(spath) > SRFS_MAXNAMLEN)
		return (srfs_err_response(resp, SRFS_ENAMETOOLONG));

	if (!srfs_localpath(exported, spath, path))
		return (srfs_errno_response(resp));

	if (SRFS_IOBUF_LEFT(req) != sizeof(srfs_off_t) + sizeof(srfs_size_t))
		return (srfs_err_response(resp, SRFS_EIO));

	offset = srfs_iobuf_get64(req);
	replsize = MIN(SRFS_READDIR_BUFSZ, srfs_iobuf_get16(req));

	if (!(dirp = opendir(path)))
		return (srfs_errno_response(resp));

	resp->size = sizeof(srfs_response_t) + replsize;

	for (idx = 0; (dire = readdir(dirp));) {
		if (idx < offset)
			continue;

		len = strlen(dire->d_name);
		if (len > SRFS_MAXNAMLEN)
			continue; /* TODO: probably not the best action */

		rde.d_type = dire->d_type;
		bcopy(dire->d_name, rde.d_name, len + 1);
		if (!srfs_iobuf_addptr(resp, (char *)&rde, len + 2))
			break;
	}

	closedir(dirp);

	return (1);
}

void
srfs_request_handle(srfs_request_t *req)
{
	srfs_server_func_t svrfunc;
	srfs_response_t resp, *r;
	srfs_iobuf_t sendbuf;
	srfs_iobuf_t reqbuf;

	req->r_size = ntohs(req->r_size);
	req->r_opcode = ntohs(req->r_opcode);

	SRFS_IOBUF_INIT(&reqbuf);
	SRFS_IOBUF_INIT(&sendbuf);
	resp.r_serial = req->r_serial;
	resp.r_size = 0;
	resp.r_errno = SRFS_OK;
	srfs_iobuf_addptr(&sendbuf, (char *)&resp, sizeof(srfs_response_t));

	if (req->r_size > SRFS_IOBUFSZ) {
		srfs_err_response(&sendbuf, SRFS_EIO);
		srfs_sock_write_sync(sendbuf.buf, sizeof(srfs_response_t));
		return;
	}

	if (req->r_size) {
		if (!srfs_sock_read_sync(reqbuf.buf, req->r_size))
			return;
		reqbuf.size = req->r_size;
	} else {
		reqbuf.size = 0;
	}

	if (req->r_opcode >= SRFS_OPCODE_MAX)
		svrfunc = srfs_funcprocs[SRFS_OPCODE_MAX].func;
	else
		svrfunc = srfs_funcprocs[req->r_opcode].func;

	if (svrfunc(&reqbuf, &sendbuf)) {
		r = SRFS_IOBUF_RESPONSE(&sendbuf);
		sendbuf.size = SRFS_IOBUF_SIZE(&sendbuf);
		r->r_size = htons(sendbuf.size - sizeof(srfs_response_t));
		r->r_errno = htons(r->r_errno);
		srfs_sock_write_sync(sendbuf.buf, sendbuf.size);
	}
}

char *
srfs_opcode(srfs_opcode_t opcode)
{
	if (opcode >= SRFS_OPCODE_MAX)
		return ("INVALID OPCODE");

	return srfs_opcodes[opcode];
}
