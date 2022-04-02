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

#ifndef _SRFS_CLIENT_H
#define _SRFS_CLIENT_H

#include <sys/stat.h>
#include <sys/statvfs.h>

#include "srfs_protocol.h"

typedef struct srfs_dirlist srfs_dirlist_t;

extern void srfs_client_init(void);

extern int srfs_client_connect(char *server, char *path);

extern size_t srfs_maxpacketsize(void);

extern void srfs_set_usrctx(uid_t uid, gid_t gid);
extern int srfs_client_user_login(void);

extern int srfs_client_host_login(void);

extern int srfs_client_mount(char *share);

extern int srfs_client_statvfs(char *share, struct statvfs *vfs);

extern int srfs_client_stat(char *path, struct stat *st);

extern srfs_dirlist_t *srfs_client_opendir(char *path, off_t offset);
extern srfs_dirent_t *srfs_client_readdir(srfs_dirlist_t *dirlist);
extern void srfs_client_closedir(srfs_dirlist_t *dirlist);

extern int srfs_client_read(char *path, off_t offset, size_t size, char *buf);
extern int srfs_client_write(char *path, off_t offset, size_t size, char *buf);

extern int srfs_client_access(char *path, int mode);
extern int srfs_client_create(char *path, int mode);

extern int srfs_client_unlink(char *path);

extern int srfs_client_mkdir(char *path, mode_t mode);
extern int srfs_client_rmdir(char *path);

extern int srfs_client_chown(char *path, uid_t uid, gid_t gid);
extern int srfs_client_chmod(char *path, mode_t mode);

extern int srfs_client_link(char *pointee, char *pointer);
extern int srfs_client_symlink(char *pointee, char *pointer);
extern int srfs_client_readlink(char *path, char *buf, size_t size);

extern int srfs_client_rename(char *src, char *dst);

extern srfs_id_t srfs_serial(void);
extern int srfs_request(srfs_opcode_t opcode);
extern int srfs_response(void);

#endif
