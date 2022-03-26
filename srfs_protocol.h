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

#include <sys/types.h>

#define SRFS_PORT 2050		/* Default TCP listen port for connections */
#define SRFS_IDENT "SRFS100"	/* SRFS identification string, sent upon
				 * succesful connection by the server */

#define SRFS_MAXNAMLEN 255	/* maximum length of share and filename */
#define SRFS_MAXPATHLEN	1024	/* maximum length of a full pathname */
#define SRFS_MAXLOGNAMELEN 33	/* maximum length of a username incl NULL */
#define SRFS_MAXGRPNAMELEN 33	/* maximum length of a group name incl NULL */

#define SRFS_READDIR_BUFSZ 1024	/* default size of READDIR buffer size */ 

/* SRFS opcodes */
#define SRFS_MOUNT	0	/* Mount a remote filesystem / directory */

#define SRFS_STATVFS	1	/* Get infor about a remote filesystem */

#define SRFS_LOGIN	2	/* Login a client user */

#define SRFS_READDIR	3	/* Read the next entry from the directory */

#define SRFS_STAT	4	/* Get file info */
#define SRFS_READ	5	/* Read data from a file */
#define SRFS_WRITE	6	/* Write data to a file */

#define SRFS_ACCESS	7	/* Check file access */

#define SRFS_OPCODE_MAX	8	/* Defines the number of opcodes */

/* SRFS status  codes */
#define SRFS_OK		0
#define SRFS_ENOENT	1
#define SRFS_EIO	2
#define SRFS_EBADF	3
#define SRFS_EACCESS	4
#define SRFS_EXIST	5
#define SRFS_ENOTDIR	6
#define SRFS_EISDIR	7
#define SRFS_EINVAL	8
#define SRFS_EINFILE	9
#define SRFS_ETXTBSY	10
#define SRFS_EFBIG	11
#define SRFS_ENOSPC	28
#define SRFS_ESEEK	29
#define SRFS_EROFS	30
#define SRFS_EAGAIN	31
#define SRFS_ENOTSUP	32
#define SRFS_ENAMETOOLONG 33

typedef uint64_t srfs_id_t;	/* Every request has a unique ID
				 * included by the response. */
typedef uint16_t srfs_size_t;	/* size of payload data */
typedef uint16_t srfs_opcode_t;	/* request opcode */
typedef uint16_t srfs_errno_t;	/* error code */

typedef struct __attribute__((__packed__)) srfs_request {
	srfs_id_t r_serial;
	srfs_size_t r_size;
	srfs_opcode_t r_opcode;
	/* payload data... */
} srfs_request_t;

typedef struct __attribute__((__packed__)) srfs_response {
	srfs_id_t r_serial;
	srfs_size_t r_size;
	srfs_errno_t r_errno;
	/* payload data... */
} srfs_response_t;

typedef uint64_t srfs_fsblkcnt_t;
typedef uint64_t srfs_fsfilcnt_t;
typedef uint64_t srfs_ulong_t;

typedef struct __attribute((__packed__)) srfs_statvfs {
	srfs_fsblkcnt_t f_bavail;
	srfs_fsblkcnt_t f_bfree;
	srfs_fsblkcnt_t f_blocks;
	srfs_fsfilcnt_t f_favail;
	srfs_fsfilcnt_t f_ffree;
	srfs_fsfilcnt_t f_files;
	srfs_ulong_t f_bsize;
	srfs_ulong_t f_flag;
	srfs_ulong_t f_frsize;
	srfs_ulong_t f_fsid;
	srfs_ulong_t f_namemax;
} srfs_statvfs_t;

typedef uint16_t srfs_dev_t;
typedef uint64_t srfs_ino_t;
typedef uint16_t srfs_nlink_t;
typedef uint16_t srfs_fflags_t;
typedef uint64_t srfs_time_t;
typedef uint32_t srfs_nsec_t;
typedef uint64_t srfs_off_t;
typedef uint32_t srfs_blksize_t;
typedef uint64_t srfs_blkcnt_t;
typedef uint16_t srfs_mode_t;

typedef struct __attribute__((__packed__)) srfs_timespec {
	srfs_time_t tv_sec;
	srfs_nsec_t tv_nsec;
} srfs_timespec_t;

typedef struct __attribute__((__packed__)) srfs_stat {
	srfs_ino_t st_ino;
	srfs_off_t st_size;
	srfs_blkcnt_t st_blocks;
	struct srfs_timespec st_atim;
	struct srfs_timespec st_mtim;
	struct srfs_timespec st_ctim;
	srfs_blksize_t st_blksize;
	srfs_mode_t st_mode;
	srfs_dev_t st_dev;
	srfs_nlink_t st_nlink;
	srfs_fflags_t st_flags;
	srfs_size_t st_usrgrpsz;	/* size of trailing user & group str */
	/* null-terminated user- and groupname... */
} srfs_stat_t;

typedef struct srfs_dirent {
	uint8_t d_type;
	char d_name[SRFS_MAXNAMLEN + 1];
} srfs_dirent_t;

#endif
