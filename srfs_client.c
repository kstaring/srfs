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

int
srfs_mount(char *share)
{
	char buf[sizeof(srfs_request_t) + 255];
	uint16_t rbuf;
	srfs_request_t *req;
	srfs_response_t resp;
	size_t len;

	if ((len = strlen(share)) > 255) {
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

	if (!srfs_sock_read_sync((char *)&rbuf, 2)) {
		return (0);
	}

	return (1);
}

srfs_id_t
srfs_request_id(void)
{
	srfs_id_t res;

	res = request_id;
	request_id++;

	return (res);
}
