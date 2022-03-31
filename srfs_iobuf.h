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

#ifndef _SRFS_IOBUF_H
#define _SRFS_IOBUF_H

#include "srfs_protocol.h"

#define SRFS_IOBUFSZ 262144
typedef struct srfs_iobuf {
        char *buf;
        char *ptr;
	size_t size;
	size_t bufsize;
} srfs_iobuf_t;

#define SRFS_IOBUF_RESET(x)		{ (x)->ptr = (x)->buf; (x)->size = (x)->bufsize; }
#define SRFS_IOBUF_SIZE(x)		((x)->ptr - (x)->buf)
#define SRFS_IOBUF_LEFT(x)		((x)->size - SRFS_IOBUF_SIZE(x))

#define SRFS_IOBUF_REQUEST(x)		((srfs_request_t *)(x)->buf)
#define SRFS_IOBUF_RESPONSE(x)		((srfs_response_t *)(x)->buf)

inline srfs_iobuf_t *
srfs_iobuf_alloc(size_t size)
{
	srfs_iobuf_t *res;

	res = malloc(sizeof(srfs_iobuf_t));
	res->buf = malloc(size);
	res->bufsize = size;

	SRFS_IOBUF_RESET(res);

	return (res);
}

inline int
srfs_iobuf_addptr(srfs_iobuf_t *buf, char *ptr, size_t size)
{
	if (SRFS_IOBUF_LEFT(buf) < size)
		return (0);

	bcopy(ptr, buf->ptr, size);
	buf->ptr += size;

	return (1);
}

inline int
srfs_iobuf_addstr(srfs_iobuf_t *buf, char *str)
{
	return (srfs_iobuf_addptr(buf, str, strlen(str) + 1));
}

inline int
srfs_iobuf_add8(srfs_iobuf_t *buf, uint8_t val)
{
	if (SRFS_IOBUF_LEFT(buf) < 1)
		return (0);

	*buf->ptr = val;
	buf->ptr++;

	return (1);
}

inline int
srfs_iobuf_add16(srfs_iobuf_t *buf, uint16_t val)
{
	if (SRFS_IOBUF_LEFT(buf) < 2)
		return (0);

	*((uint16_t *)buf->ptr) = htons(val);
	buf->ptr += 2;

	return (1);
}

inline int
srfs_iobuf_add32(srfs_iobuf_t *buf, uint32_t val)
{
	if (SRFS_IOBUF_LEFT(buf) < 4)
		return (0);

	*((uint32_t *)buf->ptr) = htobe32(val);
	buf->ptr += 4;

	return (1);
}

inline int
srfs_iobuf_add64(srfs_iobuf_t *buf, uint64_t val)
{
	if (SRFS_IOBUF_LEFT(buf) < 8)
		return (0);

	*((uint64_t *)buf->ptr) = htobe64(val);
	buf->ptr += 8;

	return (1);
}

inline char *
srfs_iobuf_getptr(srfs_iobuf_t *buf, size_t size)
{
	char *res;

	if (SRFS_IOBUF_LEFT(buf) < size)
		return (NULL);

	res = buf->ptr;
	buf->ptr += size;

	return (res);
}

inline char *
srfs_iobuf_getstr(srfs_iobuf_t *buf)
{
	char *res;

	for (int i = 0; i < SRFS_IOBUF_LEFT(buf); i++) {
		if (buf->ptr[i] == '\0') {
			res = buf->ptr;
			buf->ptr += i + 1;

			return (res);
		}
	}

	return (NULL);
}

inline uint8_t
srfs_iobuf_get8(srfs_iobuf_t *buf)
{
	uint8_t res;

	res = *buf->ptr;
	buf->ptr++;

	return (res);
}

inline uint16_t
srfs_iobuf_get16(srfs_iobuf_t *buf)
{
	uint16_t res;

	res = ((uint16_t *)buf->ptr)[0];
	buf->ptr += 2;

	return (ntohs(res));
}

inline uint32_t
srfs_iobuf_get32(srfs_iobuf_t *buf)
{
	uint32_t res;

	res = ((uint32_t *)buf->ptr)[0];
	buf->ptr += 4;

	return (be32toh(res));
}

inline uint64_t
srfs_iobuf_get64(srfs_iobuf_t *buf)
{
	uint64_t res;

	res = ((uint64_t *)buf->ptr)[0];
	buf->ptr += 8;

	return (be64toh(res));
}

#endif
