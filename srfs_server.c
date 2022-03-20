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

#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/endian.h>
#include <arpa/inet.h>

#include "srfs_server.h"
#include "srfs_exports.h"
#include "srfs_sock.h"
#include "srfs_protocol.h"

#define RESPONSE_SIZE(x) sizeof(srfs_response_t) + x

static char *srfs_opcodes[] = {
	"SRFS_MOUNT",
	"SRFS_LOGIN",
	"SRFS_OPENDIR",
	"SRFS_CLOSEDIR",
	"SRFS_READDIR",
	"SRFS_STAT",
	"SRFS_OPEN",
	"SRFS_CLOSE",
	"SRFS_READ",
	"SRFS_WRITE"
};

/* TODO only temporary, POC */
static srfs_export_t *exported;

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

static srfs_response_t *
srfs_response_fill(srfs_request_t *request, char *buf, size_t payload_size)
{
	srfs_response_t *res;

	res = (srfs_response_t *)buf;
	res->request_id = request->request_id;
	res->response_size = htons(payload_size);

	return (res);
}

static void
srfs_status_response(srfs_request_t *request, srfs_errno_t status)
{
	char buf[RESPONSE_SIZE(sizeof(srfs_errno_t))];
	srfs_errno_t *st;

	srfs_response_fill(request, buf, sizeof(uint16_t));
	st = (srfs_errno_t *)((char *)buf + sizeof(srfs_response_t));
	*st = htons(status);

	srfs_sock_write_sync(buf, sizeof(buf));
}

static void
srfs_errno_response(srfs_request_t *request)
{
	srfs_errno_t status;

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

	srfs_status_response(request, status);
}

static void
srfs_not_implemented(srfs_request_t *request)
{
	srfs_status_response(request, SRFS_ENOTSUP);
}

static void
srfs_invalid_opcode(srfs_request_t *request)
{
	srfs_status_response(request, SRFS_EINVAL);
}

static void
srfs_mount(srfs_request_t *request)
{
	char share[SRFS_MAXSHARELEN + 1];
	srfs_export_t *export;

	if (request->request_size > SRFS_MAXSHARELEN)
		return srfs_status_response(request, SRFS_ENAMETOOLONG);

	srfs_sock_read_sync(share, request->request_size);
	share[request->request_size] = '\0';

	if (!(export = srfs_export_by_sharename(share)))
		return srfs_status_response(request, SRFS_ENOENT);

	exported = export;

	return (srfs_status_response(request, SRFS_OK));
}

static void
srfs_stat(srfs_request_t *request)
{
	char rbuf[sizeof(srfs_errno_t) + sizeof(srfs_stat_t) + SRFS_MAXLOGNAMELEN + SRFS_MAXGRPNAMELEN];
	char spath[SRFS_MAXPATHLEN + 1];
	char path[SRFS_MAXPATHLEN + 1];
	char *usrname, *grpname;
	srfs_errno_t *status;
	struct passwd *pwd;
	size_t ulen, glen;
	struct group *gr;
	srfs_stat_t *rst;
	char *usrgrpbuf;
	struct stat st;

	status = (srfs_errno_t *)rbuf;
	rst = (srfs_stat_t *)(rbuf + sizeof(srfs_errno_t));
	usrgrpbuf = rbuf + sizeof(srfs_errno_t) + sizeof(srfs_stat_t);

	if (request->request_size > SRFS_MAXPATHLEN)
		return srfs_status_response(request, SRFS_ENAMETOOLONG);

	srfs_sock_read_sync(path, request->request_size);
	path[request->request_size] = '\0';

	if (!srfs_localpath(exported, path, spath))
		return srfs_errno_response(request);

	if (stat(spath, &st) != 0)
		return srfs_errno_response(request);

	if ((pwd = getpwuid(st.st_uid)))
		usrname = pwd->pw_name;
	else
		usrname = "nobody";
	if ((gr = getgrgid(st.st_gid)))
		grpname = gr->gr_name;
	else
		grpname = "nogroup";

	ulen = MIN(strlen(usrname), SRFS_MAXLOGNAMELEN - 1);
	glen = MIN(strlen(grpname), SRFS_MAXGRPNAMELEN - 1);
	strncpy(usrgrpbuf, usrname, ulen);
	usrgrpbuf[ulen] = '\0';
	strncpy(usrgrpbuf + ulen + 1, grpname, glen);
	usrgrpbuf[ulen + glen + 1] = '\0';

	rst->st_ino = htobe64(rst->st_ino);
	rst->st_size = htobe64(rst->st_size);
	rst->st_blocks = htobe64(rst->st_blocks);
	rst->st_atim.tv_sec = htobe64(rst->st_atim.tv_sec);
	rst->st_atim.tv_nsec = htobe32(rst->st_atim.tv_nsec);
	rst->st_mtim.tv_sec = htobe64(rst->st_mtim.tv_sec);
	rst->st_mtim.tv_nsec = htobe32(rst->st_mtim.tv_nsec);
	rst->st_ctim.tv_sec = htobe64(rst->st_ctim.tv_sec);
	rst->st_ctim.tv_nsec = htobe32(rst->st_ctim.tv_nsec);
	rst->st_blksize = htobe32(rst->st_blksize);
	rst->st_mode = htons(rst->st_mode);
	rst->st_dev = htons(rst->st_dev);
	rst->st_nlink = htons(rst->st_nlink);
	rst->st_flags = htons(rst->st_flags);
	rst->st_usrgrpsz = ulen + glen + 2;

	*status = SRFS_OK;

	srfs_sock_write_sync(rbuf, sizeof(rbuf));
}

void
srfs_request_handle(srfs_request_t *request)
{
	request->request_size = ntohs(request->request_size);
	request->opcode = ntohs(request->opcode);

	switch (request->opcode) {
	case SRFS_MOUNT: return srfs_mount(request);
	case SRFS_LOGIN: return srfs_not_implemented(request);
	case SRFS_OPENDIR: return srfs_not_implemented(request);
	case SRFS_CLOSEDIR: return srfs_not_implemented(request);
	case SRFS_READDIR: return srfs_not_implemented(request);
	case SRFS_STAT: return srfs_stat(request);
	case SRFS_OPEN: return srfs_not_implemented(request);
	case SRFS_CLOSE: return srfs_not_implemented(request);
	case SRFS_READ: return srfs_not_implemented(request);
	case SRFS_WRITE: return srfs_not_implemented(request);
	default: return srfs_invalid_opcode(request);
	}
}

char *
srfs_opcode(srfs_opcode_t opcode)
{
	if (opcode >= SRFS_OPCODE_MAX)
		return ("INVALID OPCODE");

	return srfs_opcodes[opcode];
}
