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
#include <netdb.h>
#include <unistd.h>
#include <sys/endian.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "srfs_client.h"
#include "srfs_sock.h"

static srfs_id_t request_id;

static srfs_request_t *srfs_request_fill(srfs_request_t *request,
	srfs_opcode_t opcode, srfs_size_t payload_size);

static srfs_request_t *
srfs_request_fill(srfs_request_t *request, srfs_opcode_t opcode,
		  srfs_size_t payload_size)
{
	request->request_id = htobe64(request_id);
	request->opcode = htons(opcode);
	request->request_size = htons(payload_size);

	return (request);
}

srfs_id_t
srfs_request_id(void)
{
	srfs_id_t res;

	res = request_id;
	request_id++;

	return (res);
}

int
srfs_request_path(char *path, srfs_opcode_t opcode, char *rbuf, size_t bufsize)
{
	char buf[sizeof(srfs_request_t) + SRFS_MAXPATHLEN];
	srfs_request_t *req;
	size_t len;

	if ((len = strlen(path)) > SRFS_MAXPATHLEN) {
		errno = ENAMETOOLONG;
		return (0);
	}

	req = (srfs_request_t *)buf;
	srfs_request_fill(req, opcode, strlen(path));
	bcopy(path, buf + sizeof(srfs_request_t), len);

	if (!srfs_sock_write_sync(buf, sizeof(srfs_request_t) + len))
		return (0);

	if (!srfs_sock_read_sync(rbuf, bufsize))
		return (0);

	return (1);
}

int
srfs_mount(char *share)
{
	char buf[sizeof(srfs_request_t) + SRFS_MAXSHARELEN];
	srfs_request_t *req;
	srfs_response_t resp;
	uint16_t rbuf;
	size_t len;

	if ((len = strlen(share)) > SRFS_MAXSHARELEN) {
		errno = ENAMETOOLONG;
		return (0);
	}

	req = (srfs_request_t *)buf;
	srfs_request_fill(req, SRFS_MOUNT, strlen(share));
	bcopy(share, buf + sizeof(srfs_request_t), len);

	if (!srfs_sock_write_sync(buf, sizeof(srfs_request_t) + len))
		return (0);

	if (!srfs_sock_read_sync((char *)&resp, sizeof(srfs_response_t)))
		return (0);

	if (ntohs(resp.response_size) != 2)
		return (0);

	if (!srfs_sock_read_sync((char *)&rbuf, 2))
		return (0);

	return (1);
}

int
srfs_client_stat(char *path, struct stat *st)
{
	char usrgrpbuf[SRFS_MAXLOGNAMELEN + SRFS_MAXGRPNAMELEN];
	struct passwd *pwd = NULL;
	struct group *gr = NULL;
	char *usrname, *grpname;
	srfs_stat_t rst;
	srfs_size_t len;
	uid_t uid;
	gid_t gid;

	if (!srfs_request_path(path, SRFS_STAT, (char *)&rst, sizeof(srfs_stat_t)))
		return (0);

	len = ntohs(rst.st_usrgrpsz);
	if (len < 4 || len > SRFS_MAXLOGNAMELEN + SRFS_MAXGRPNAMELEN) {
		errno = EIO;
		return (0);
	}

	if (!srfs_sock_read_sync((char *)&usrgrpbuf, len))
		return (0);

	usrname = usrgrpbuf;
	if (!(grpname = index(usrgrpbuf, '\0')))
		return (0);
	grpname++;
	if (!strlen(usrname) || !strlen(grpname)) {
		errno = EIO;
		return (0);
	}

	if (!(pwd = getpwnam(usrname)))
		pwd = getpwnam("nobody");
	if (pwd)
		uid = pwd->pw_uid;
	else
		uid = 65534;

	if (!(gr = getgrnam(grpname)))
		gr = getgrnam("nogroup");
	if (gr)
		gid = gr->gr_gid;
	else
		gid = 65533;

	st->st_ino = be64toh(rst.st_ino);
	st->st_size = be64toh(rst.st_size);
	st->st_blocks = be64toh(rst.st_blocks);
	st->st_atim.tv_sec = be64toh(rst.st_atim.tv_sec);
	st->st_atim.tv_nsec = be32toh(rst.st_atim.tv_nsec);
	st->st_mtim.tv_sec = be64toh(rst.st_mtim.tv_sec);
	st->st_mtim.tv_nsec = be64toh(rst.st_mtim.tv_nsec);
	st->st_ctim.tv_sec = be64toh(rst.st_ctim.tv_sec);
	st->st_ctim.tv_nsec = be64toh(rst.st_ctim.tv_nsec);
	st->st_blksize = be32toh(rst.st_blksize);
	st->st_mode = htons(rst.st_mode);
	st->st_dev = htons(rst.st_dev);
	st->st_nlink = htons(rst.st_nlink);
	st->st_flags = htons(rst.st_flags);
	st->st_uid = uid;
	st->st_gid = gid;

	return (1);
}
