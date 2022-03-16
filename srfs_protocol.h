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

#ifndef _SRFS_PROTOCOL_H
#define _SRFS_PROTOCOL_H

#define SRFS_PORT 2050		/* Default TCP listen port for connections */
#define SRFS_IDENT "SRFS100"	/* SRFS identification string, sent upon
				 * succesful connection by the server */

typedef uint64_t srfs_id_t;	/* Every request has a unique ID
				 * included by the response. */

typedef enum {
	SRFS_USERS = 0,	/* Client users and their uids are sent to the server,
			 * as well as the groups on the client and
			 * corresponding gids.
			 * The server translates server ids to client ids
			 * and vice verse. To do this, it needs this
			 * information from the client. This is the first
			 * action a client must perform after connecting */

	SRFS_LOGIN,	/* Login a client user. */
	SRFS_AUTH_KEYS,	/* Login a client user using their
			 * authorized_keys file. */

	SRFS_MOUNT,	/* Mount a remote filesystem / directory */

	SRFS_OPENDIR,	/* Open a directory to read its listing */
	SRFS_READDIR,	/* Read the next entry from the directory listing */
	SRFS_CLOSEDIR,	/* Close the directory */

	SRFS_STAT,	/* Get stat_t info */
	SRFS_OPEN,	/* Open a file for reading or writing */
	SRFS_READ,	/* Read data from a file */
	SRFS_WRITE,	/* Write data to a file */
	SRFS_CLOSE,	/* Close a file */

	SRFS_OPCODE_MAX	/* Defines the number of opcodes */
} srfs_opcode_t;

typedef uint32_t srfs_size_t;	/* size of payload data */
typedef struct {
	srfs_opcode_t opcode;
	srfs_id_t request_id;
	srfs_size_t request_size;
	/* payload data... */
} srfs_request_t;

typedef struct {
	srfs_id_t request_id;
	srfs_size_t response_size;
	/* payload data... */
} srfs_response_t;

#endif
