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

#include <arpa/inet.h>

#include "srfs_server.h"
#include "srfs_exports.h"
#include "srfs_sock.h"

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
	char share[256];
	srfs_export_t *export;

	if (request->request_size > 255)
		return srfs_status_response(request, SRFS_EINVAL);

	srfs_sock_read_sync(share, request->request_size);
	share[request->request_size] = '\0';

	if (!(export = srfs_export_by_sharename(share)))
		return srfs_status_response(request, SRFS_ENOENT);

	return srfs_status_response(request, SRFS_OK);
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
	case SRFS_STAT: return srfs_not_implemented(request);
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
