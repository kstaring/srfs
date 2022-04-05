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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/endian.h>
#include <sys/statvfs.h>
#include <arpa/inet.h>


#include "srfs_pki.h"
#include "srfs_sock.h"
#include "srfs_iobuf.h"
#include "srfs_config.h"
#include "srfs_usrgrp.h"
#include "srfs_server.h"
#include "srfs_exports.h"
#include "srfs_protocol.h"

#define RESPONSE_SIZE(x) sizeof(srfs_response_t) + x

typedef struct srfs_file_cache {
	char *path;
	int mode;
	int fd;
	off_t offset;
	time_t timestamp;
	LIST_ENTRY(srfs_file_cache) list;
} srfs_file_t;
LIST_HEAD(file_cache, srfs_file_cache);
static struct file_cache file_cache = LIST_HEAD_INITIALIZER(file_cache);

typedef struct srfs_dir_cache {
	char *path;
	DIR *d;
	time_t timestamp;
	LIST_ENTRY(srfs_dir_cache) list;
} srfs_dir_t;
LIST_HEAD(dir_cache, srfs_dir_cache);
static struct dir_cache dir_cache = LIST_HEAD_INITIALIZER(dir_cache);

typedef int (*srfs_server_func_t)(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static char *srfs_opcodes[] = {
	"SRFS_MOUNT",
	"SRFS_STATVFS",
	"SRFS_LOGIN",
	"SRFS_READDIR",
	"SRFS_STAT",
	"SRFS_CREATE",
	"SRFS_READ",
	"SRFS_WRITE",
	"SRFS_ACCESS",
	"SRFS_CHMOD",
	"SRFS_CHOWN",
	"SRFS_MKDIR",
	"SRFS_RMDIR",
	"SRFS_LINK",
	"SRFS_SYMLINK",
	"SRFS_READLINK",
	"SRFS_UNLINK",
	"SRFS_RENAME"
};

static int srfs_get_path(srfs_iobuf_t *req, char *path);
static int srfs_get_path_nonexistent(srfs_iobuf_t *req, char *path);

//static int srfs_not_implemented(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_invalid_opcode(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_need_auth(srfs_iobuf_t *req, srfs_iobuf_t *resp);

static int srfs_mount(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_login(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_statvfs(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_readdir(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_stat(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_create(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_read(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_write(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_access(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_unlink(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_mkdir(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_rmdir(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_chown(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_chmod(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_link(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_symlink(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_readlink(srfs_iobuf_t *req, srfs_iobuf_t *resp);
static int srfs_rename(srfs_iobuf_t *req, srfs_iobuf_t *resp);

static srfs_server_func_t srfs_server_funcs[] = {
	srfs_mount,			// SRFS_MOUNT
	srfs_statvfs,			// SRFS_STATVFS
	srfs_login,			// SRFS_LOGIN
	srfs_readdir,			// SRFS_READDIR
	srfs_stat,			// SRFS_STAT
	srfs_create,			// SRFS_CREATE
	srfs_read,			// SRFS_READ
	srfs_write,			// SRFS_WRITE
	srfs_access,			// SRFS_ACCESS
	srfs_chmod,			// SRFS_CHMOD
	srfs_chown,			// SRFS_CHOWN
	srfs_mkdir,			// SRFS_MKDIR
	srfs_rmdir,			// SRFS_RMDIR
	srfs_link,			// SRFS_LINK
	srfs_symlink,			// SRFS_SYMLINK
	srfs_readlink,			// SRFS_READLINK
	srfs_unlink,			// SRFS_UNLINK
	srfs_rename,			// SRFS_RENAME
	srfs_invalid_opcode		// SRFS_OPCODE_MAX
};

static int client_authenticated = 0;

static srfs_iobuf_t *reqbuf = NULL;
static srfs_iobuf_t *respbuf = NULL;

/* Only one mounted filesystem per connection for now */
static srfs_export_t *exported = NULL;

void
srfs_server_init(void)
{
	reqbuf = srfs_iobuf_alloc(SRFS_IOBUFSZ);
	respbuf = srfs_iobuf_alloc(SRFS_IOBUFSZ);

	LIST_INIT(&file_cache);
	LIST_INIT(&dir_cache);

	srfs_usrgrp_init();
}

void
srfs_server_periodic_cleanup(void)
{
	srfs_file_t *file, *tfile;
	srfs_dir_t *dir, *tdir;
	time_t tm;

	tm = time(NULL) - 10;

	LIST_FOREACH_SAFE(file, &file_cache, list, tfile) {
		if (file->timestamp < tm)
			LIST_REMOVE(file, list);
	}
	LIST_FOREACH_SAFE(dir, &dir_cache, list, tdir) {
		if (dir->timestamp < tm)
			LIST_REMOVE(dir, list);
	}
}

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
	case EPERM:	status = SRFS_EPERM; break;
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
	case ENEEDAUTH: status = SRFS_ENEEDAUTH; break;
	default:
		printf("srfs_errno_response: unhandled errno: %d\n", errno);
		status = EIO;
	}

	resp->r_errno = status;
	resp->r_size = 0;

	return (1);
}

/*
static int
srfs_not_implemented(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
printf("not implemented!\n");
	return (srfs_err_response(resp, SRFS_ENOTSUP));
}
*/

static int
srfs_invalid_opcode(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
printf("invalid opcode!\n");
	return (srfs_err_response(resp, SRFS_EINVAL));
}

static int
srfs_need_auth(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
printf("need auth!\n");
	return (srfs_err_response(resp, SRFS_ENEEDAUTH));
}

static int
srfs_verify_host(char *buf, size_t sz)
{
	char path[MAXPATHLEN + 1];
	struct dirent *dire;
	int res = 0;
	DIR *dirp;

	if (!(dirp = opendir(SRFS_CLIENT_KEYS_DIR)))
		return (0);

	for(; (dire = readdir(dirp));) {
		if (dire->d_name[0] == '.')
			continue;
		if (snprintf(path, MAXPATHLEN + 1, "%s/%s",
			     SRFS_CLIENT_KEYS_DIR, dire->d_name) == MAXPATHLEN)
			continue;

		if (srfs_rsa_verify_path(path, sign_challenge(),
					 SRFS_CHALLENGE_SZ, buf, sz)) {
			syslog(LOG_AUTH | LOG_INFO, "%s: host authenticated "
			       "with host key %s", srfs_remote_ipstr(),
			       dire->d_name);
			res = 1;
			break;
		}
	}

	closedir(dirp);

	if (!res)
		syslog(LOG_AUTH | LOG_NOTICE, "%s: host failed authentication"
		       "with host keys", srfs_remote_ipstr());

	return (res);
}

static int
srfs_verify_user(char *usrname, char *buf, size_t sz)
{
	char path[MAXPATHLEN + 1];
	int res = 0;
	char *home;
	uid_t uid;

	if (srfs_usrisnobody(usrname))
		return (0);

	uid = srfs_uidbyname(usrname);
	if (!(home = srfs_homebyuid(uid))) {
		syslog(LOG_AUTH | LOG_NOTICE, "%s: user %s failed "
		       "authentication: no homedir", srfs_remote_ipstr(),
		       usrname);
		return (0);
	}

	if (snprintf(path, MAXPATHLEN + 1, "%s/.srfs/id_rsa.pub",
		     home) == MAXPATHLEN) {
		syslog(LOG_AUTH | LOG_NOTICE, "%s: user %s failed "
		       "authentication: path too long", srfs_remote_ipstr(),
		       usrname);
		return (0);
	}

	if (srfs_rsa_verify_path(path, sign_challenge(), SRFS_CHALLENGE_SZ,
				 buf, sz)) {
		res = 1;
		client_authenticated = 1;
		sfrs_set_authenticated(usrname);
		syslog(LOG_AUTH | LOG_INFO, "%s: user %s authenticated "
		       "with user key %s", srfs_remote_ipstr(), usrname, path);
	} else {
		syslog(LOG_AUTH | LOG_NOTICE, "%s: user %s failed "
		       "authentication with key %s", srfs_remote_ipstr(),
		       usrname, path);
	}

	return (res);
}

static int
srfs_login(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char *buf, *usrname;
	srfs_auth_t auth;
	size_t sz;

	if (SRFS_IOBUF_LEFT(req) < 1)
		return (srfs_err_response(resp, SRFS_EIO));

	auth = srfs_iobuf_get8(req);

	switch (auth) {
	case SRFS_AUTH_HOST:
		buf = req->ptr;
		sz = SRFS_IOBUF_LEFT(req);
		if (!srfs_verify_host(buf, sz))
			return (srfs_err_response(resp, SRFS_EACCESS));
		client_authenticated = 1;
		break;
	case SRFS_AUTH_SRFS:
		if (!(usrname = srfs_iobuf_getstr(req)))
			return (srfs_err_response(resp, SRFS_EIO));
		buf = req->ptr;
		sz = SRFS_IOBUF_LEFT(req);
		if (!srfs_verify_user(usrname, buf, sz))
			return (srfs_err_response(resp, SRFS_EACCESS));
		client_authenticated = 1;
		break;
	case SRFS_AUTH_SSH: break;
	case SRFS_AUTH_PWD: break;
	default: return (srfs_err_response(resp, SRFS_ENOTSUP));
	}

	return (1);
}

static int
srfs_mount(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	srfs_export_t *export;
	char *share;

	if (exported)
		return (srfs_err_response(resp, SRFS_EXIST));

	if (req->size > SRFS_MAXNAMLEN + 1)
		return (srfs_err_response(resp, SRFS_ENAMETOOLONG));

	if (!(share = srfs_iobuf_getstr(req)))
		return (srfs_err_response(resp, SRFS_EIO));

	if (!(export = srfs_export_by_sharename(share)))
		return (srfs_err_response(resp, SRFS_ENOENT));

	exported = export;

	return (1);
}

static int
srfs_get_usrctx(srfs_iobuf_t *req)
{
	char *usrname;
	char *grpname;
	uid_t uid;
	gid_t gid;

	if (!(usrname = srfs_iobuf_getstr(req)))
		return (0);
	if (!(grpname = srfs_iobuf_getstr(req)))
		return (0);

	uid = srfs_uidbyname(usrname);
	gid = srfs_gidbyuid(uid);

	if (uid == 0 || !srfs_uid_authenticated(uid)) {
		uid = srfs_uidbyname("nobody");
		gid = srfs_gidbyname("nogroup");
	}

	if (getuid() == 0) {
		seteuid(0);
		setegid(gid);
		seteuid(uid);
	}

	return (1);
}

static int
srfs_translate_path(srfs_iobuf_t *req, char *path)
{
	char *spath;

	if (!(spath = srfs_iobuf_getstr(req))) {
		errno = EIO;
		return (0);
	}

	if (strlen(spath) > SRFS_MAXNAMLEN) {
		errno = ENAMETOOLONG;
		return (0);
	}

	if (!srfs_localpath(exported, spath, path))
		return (0);

	return (1);
}

static int
srfs_translate_path_nonexistent(srfs_iobuf_t *req, char *path)
{
	char tmp[SRFS_MAXPATHLEN + 1];
	char *spath, *sep;

	if (!(spath = srfs_iobuf_getstr(req))) {
		errno = EIO;
		return (0);
	}

	if (strlen(spath) > SRFS_MAXNAMLEN) {
		errno = ENAMETOOLONG;
		return (0);
	}

	if (!(sep = rindex(spath, '/'))) {
		errno = EIO;
		return (0);
	}
	*sep = '\0';

	if (!srfs_localpath(exported, spath, tmp))
		return (0);

	if (snprintf(path, SRFS_MAXPATHLEN + 1, "%s/%s", tmp,
		     sep + 1) == SRFS_MAXPATHLEN) {
		errno = ENAMETOOLONG;
		return (0);
	}

	return (1);
}

static int
srfs_get_path(srfs_iobuf_t *req, char *path)
{
	if (!srfs_get_usrctx(req)) {
		errno = EIO;
		return (0);
	}

	if (!srfs_translate_path(req, path))
		return (0);

	return (1);
}

static int
srfs_get_path_nonexistent(srfs_iobuf_t *req, char *path)
{
	if (!srfs_get_usrctx(req)) {
		errno = EIO;
		return (0);
	}

	if (!srfs_translate_path_nonexistent(req, path))
		return (0);

	return (1);
}

static int
srfs_statvfs(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	srfs_statvfs_t svfs;
	struct statvfs vfs;
	uint64_t namelen;

	if (!srfs_get_path(req, path))
		return (srfs_errno_response(resp));

	if (statvfs(path, &vfs) == -1)
		return (srfs_errno_response(resp));

	svfs.f_bavail = htobe64(vfs.f_bavail);
	svfs.f_bfree = htobe64(vfs.f_bfree);
	svfs.f_blocks = htobe64(vfs.f_blocks);
	svfs.f_favail = htobe64(vfs.f_favail);
	svfs.f_ffree = htobe64(vfs.f_ffree);
	svfs.f_files = htobe64(vfs.f_files);
	svfs.f_bsize = htobe64(vfs.f_bsize);
	svfs.f_flag = htobe64(vfs.f_flag); // TODO when RO implemented, override
	svfs.f_frsize = htobe64(vfs.f_frsize);
	svfs.f_fsid = htobe64(vfs.f_fsid);
	namelen = MIN(SRFS_MAXNAMLEN, vfs.f_namemax);
	svfs.f_namemax = htobe64(namelen);

	if (!srfs_iobuf_addptr(resp, (char *)&svfs, sizeof(srfs_statvfs_t)))
		return (srfs_err_response(resp, SRFS_EIO));

	return (1);
}

static int
srfs_stat(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	char *usrname, *grpname;
	srfs_stat_t rst;
	struct stat st;

	if (!srfs_get_path_nonexistent(req, path))
		return (srfs_errno_response(resp));

	if (lstat(path, &st) != 0)
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
	rst.st_mode = htobe32(st.st_mode);
	rst.st_dev = htons(st.st_dev);
	rst.st_nlink = htons(st.st_nlink);
	rst.st_flags = htons(st.st_flags);

	if (!srfs_iobuf_addptr(resp, (char *)&rst, sizeof(srfs_stat_t)))
		return (srfs_err_response(resp, SRFS_EIO));
	if (!srfs_iobuf_addstr(resp, usrname))
		return (srfs_err_response(resp, SRFS_EIO));
	if (!srfs_iobuf_addstr(resp, grpname))
		return (srfs_err_response(resp, SRFS_EIO));

	return (1);
}

static srfs_dir_t *
srfs_dir_open(char *path)
{
	srfs_dir_t *res;
	DIR *dirp;

	LIST_FOREACH(res, &dir_cache, list) {
		if (strcmp(res->path, path) == 0) {
			res->timestamp = time(NULL);
			return (res);
		}
	}

	if (!(dirp = opendir(path)))
		return (NULL);

	res = malloc(sizeof(srfs_dir_t));
	res->path = strdup(path);
	res->d = dirp;
	res->timestamp = time(NULL);

	LIST_INSERT_HEAD(&dir_cache, res, list);

	return (res);
}

static void
srfs_dir_close(srfs_dir_t *dir)
{
	LIST_REMOVE(dir, list);

	closedir(dir->d);
	free(dir->path);
	free(dir);
}

static int
srfs_readdir(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	srfs_off_t offset, idx;
	srfs_bufsz_t replsize;
	struct dirent *dire;
	srfs_dirent_t rde;
	srfs_dir_t *dir;
	size_t len;

	if (!srfs_get_path(req, path))
		return (srfs_errno_response(resp));

	if (SRFS_IOBUF_LEFT(req) != sizeof(srfs_off_t) + sizeof(srfs_bufsz_t))
		return (srfs_err_response(resp, SRFS_EIO));

	offset = srfs_iobuf_get64(req);
	replsize = srfs_iobuf_get32(req);
	replsize = MIN(SRFS_IOBUF_LEFT(resp), replsize);

	if (!(dir = srfs_dir_open(path)))
		return (srfs_errno_response(resp));

	rewinddir(dir->d);

	resp->size = sizeof(srfs_response_t) + replsize;

	for (idx = 0; (dire = readdir(dir->d)); idx++) {
		if (idx < offset)
			continue;

		len = MIN(SRFS_MAXNAMLEN, strlen(dire->d_name));

		rde.d_type = dire->d_type;
		bcopy(dire->d_name, rde.d_name, len + 1);
		if (!srfs_iobuf_addptr(resp, (char *)&rde, len + 2))
			break;
	}

	if (!dire)
		srfs_dir_close(dir);

	return (1);
}

static int
srfs_create(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	int fd, mode;

	if (!srfs_get_path_nonexistent(req, path))
		return (srfs_errno_response(resp));

	if (SRFS_IOBUF_LEFT(req) != sizeof(int))
		return (srfs_err_response(resp, SRFS_EIO));

	mode = srfs_iobuf_get32(req);

	if ((fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, mode)) == -1)
		return (srfs_errno_response(resp));

	close(fd);

	return (1);
}

static srfs_file_t *
srfs_file_open(char *path, int mode)
{
	srfs_file_t *res;
	int fd;

	LIST_FOREACH(res, &file_cache, list) {
		if (strcmp(res->path, path) == 0 && res->mode == mode) {
			res->timestamp = time(NULL);
			return (res);
		}
	}

	if (!(fd = open(path, mode)))
		return (NULL);

	res = malloc(sizeof(srfs_file_t));
	res->path = strdup(path);
	res->mode = mode;
	res->fd = fd;
	res->offset = 0;
	res->timestamp = time(NULL);

	LIST_INSERT_HEAD(&file_cache, res, list);

	return (res);
}

static void
srfs_file_close(srfs_file_t *file)
{
	LIST_REMOVE(file, list);

	close(file->fd);
	free(file->path);
	free(file);
}

static int
srfs_read(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	srfs_off_t offset;
	srfs_file_t *file;
	ssize_t len;
	size_t size;

	if (!srfs_get_path(req, path))
		return (srfs_errno_response(resp));

	offset = srfs_iobuf_get64(req);
	size = srfs_iobuf_get64(req);
	size = MIN(size, SRFS_IOBUF_LEFT(resp));

	if (!(file = srfs_file_open(path, O_RDONLY)))
		return (srfs_errno_response(resp));

	if (offset != file->offset) {
		if (lseek(file->fd, offset, SEEK_SET) == -1) {
			srfs_file_close(file);
			return (srfs_errno_response(resp));
		}
	}

	if ((len = read(file->fd, resp->ptr, size)) == -1) {
		srfs_file_close(file);
		return (srfs_errno_response(resp));
	}

	resp->ptr += len;

	file->offset = offset + len;

	return (1);
}

static int
srfs_write(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	size_t size, wsize;
	srfs_off_t offset;
	srfs_file_t *file;
	int w;

	if (!srfs_get_path(req, path))
		return (srfs_errno_response(resp));

	offset = srfs_iobuf_get64(req);
	size = wsize = SRFS_IOBUF_LEFT(req);

	if (!(file = srfs_file_open(path, O_WRONLY)))
		return (srfs_errno_response(resp));

	if (offset != file->offset) {
		if (lseek(file->fd, offset, SEEK_SET) == -1) {
			srfs_file_close(file);
			return (srfs_errno_response(resp));
		}
	}
	for (; size != 0;) {
		if ((w = write(file->fd, req->ptr, size)) == -1) {
			if (errno == EINTR)
				continue;
			srfs_file_close(file);
			return (srfs_errno_response(resp));
		}
		size -= w;
		req->ptr += w;
	}

	file->offset = offset + wsize;

	return (1);
}

static int
srfs_access(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	int mode;

	if (!srfs_get_path(req, path))
		return (srfs_errno_response(resp));

	if (SRFS_IOBUF_LEFT(req) != sizeof(int))
		return (srfs_err_response(resp, SRFS_EIO));

	mode = srfs_iobuf_get32(req);

	if (access(path, mode) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

static int
srfs_unlink(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];

	if (!srfs_get_path_nonexistent(req, path))
		return (srfs_errno_response(resp));

	if (unlink(path) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

static int
srfs_mkdir(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	mode_t mode;

	if (!srfs_get_path_nonexistent(req, path))
		return (srfs_errno_response(resp));

	if (SRFS_IOBUF_LEFT(req) != sizeof(mode_t))
		return (srfs_err_response(resp, SRFS_EIO));

	mode = srfs_iobuf_get16(req);

	if (mkdir(path, mode) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

static int
srfs_rmdir(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];

	if (!srfs_get_path(req, path))
		return (srfs_errno_response(resp));

	if (rmdir(path) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

static int
srfs_chmod(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	mode_t mode;

	if (!srfs_get_path(req, path))
		return (srfs_errno_response(resp));

	if (SRFS_IOBUF_LEFT(req) != sizeof(mode_t))
		return (srfs_err_response(resp, SRFS_EIO));

	mode = srfs_iobuf_get16(req) & 07777;

	if (chmod(path, mode) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

static int
srfs_chown(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	char *usr, *grp;

	if (!srfs_get_path(req, path))
		return (srfs_errno_response(resp));

	if (!(usr = srfs_iobuf_getstr(req)))
		return (srfs_err_response(resp, SRFS_EIO));
	if (!(grp = srfs_iobuf_getstr(req)))
		return (srfs_err_response(resp, SRFS_EIO));

	if (chown(path, srfs_uidbyname(usr), srfs_gidbyname(grp)) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

static int
srfs_readlink(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char path[SRFS_MAXPATHLEN + 1];
	char lnk[MAXPATHLEN + 1];
	ssize_t n;

	if (!srfs_get_path_nonexistent(req, path))
		return (srfs_errno_response(resp));

	if ((n = readlink(path, lnk, MAXPATHLEN)) == -1)
		return (srfs_errno_response(resp));
	lnk[n] = '\0';

	if (!srfs_iobuf_addstr(resp, lnk))
		return (srfs_err_response(resp, SRFS_EIO));

	return (1);
}

static int
srfs_link(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char src[SRFS_MAXPATHLEN + 1], dst[SRFS_MAXPATHLEN + 1];

	if (!srfs_get_path_nonexistent(req, src))
		return (srfs_errno_response(resp));

	if (!srfs_translate_path_nonexistent(req, dst))
		return (srfs_errno_response(resp));

	if (link(src, dst) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

static int
srfs_symlink(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char *src, dst[SRFS_MAXPATHLEN + 1];

	if (!srfs_get_usrctx(req)) {
		errno = EIO;
		return (0);
	}

	if (!(src = srfs_iobuf_getstr(req)))
		return (srfs_errno_response(resp));

	if (!srfs_translate_path_nonexistent(req, dst))
		return (srfs_errno_response(resp));

	if (symlink(src, dst) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

static int
srfs_rename(srfs_iobuf_t *req, srfs_iobuf_t *resp)
{
	char src[SRFS_MAXPATHLEN + 1], dst[SRFS_MAXPATHLEN + 1];

	if (!srfs_get_path(req, src))
		return (srfs_errno_response(resp));

	if (!srfs_translate_path_nonexistent(req, dst))
		return (srfs_errno_response(resp));

	if (rename(src, dst) == -1)
		return (srfs_errno_response(resp));

	return (1);
}

void
srfs_request_handle(srfs_request_t *req)
{
	srfs_server_func_t svrfunc;
	srfs_response_t resp, *r;
//	uid_t uid;
//	gid_t gid;

	req->r_size = be32toh(req->r_size);
	req->r_opcode = ntohs(req->r_opcode);

	SRFS_IOBUF_RESET(reqbuf);
	SRFS_IOBUF_RESET(respbuf);
	resp.r_serial = req->r_serial;
	resp.r_size = 0;
	resp.r_errno = SRFS_OK;
	srfs_iobuf_addptr(respbuf, (char *)&resp, sizeof(srfs_response_t));

	if (req->r_size > SRFS_IOBUF_LEFT(respbuf)) {
		// TODO communicate the maximum amount of bytes the
		// server will allow so the client can adjust its reqbuf
		srfs_err_response(respbuf, SRFS_EIO);
		srfs_sock_write_sync(respbuf->buf, sizeof(srfs_response_t));
		return;
	}

	if (req->r_size) {
		if (!srfs_sock_read_sync(reqbuf->buf, req->r_size))
			return;
		reqbuf->size = req->r_size;
	} else {
		reqbuf->size = 0;
	}

	if (req->r_opcode >= SRFS_OPCODE_MAX)
		svrfunc = srfs_server_funcs[SRFS_OPCODE_MAX];
	else
		svrfunc = srfs_server_funcs[req->r_opcode];

	/* override function if we need client authentication */
	if (!client_authenticated) {
		if (req->r_opcode != SRFS_MOUNT &&
		    req->r_opcode != SRFS_LOGIN)
			svrfunc = srfs_need_auth;
	}

	if (svrfunc(reqbuf, respbuf)) {
		r = SRFS_IOBUF_RESPONSE(respbuf);
		respbuf->size = SRFS_IOBUF_SIZE(respbuf);
		r->r_size = htobe32(respbuf->size - sizeof(srfs_response_t));
		r->r_errno = htons(r->r_errno);
		srfs_sock_write_sync(respbuf->buf, respbuf->size);
	}

//	if (getuid() == 0) {
//		uid = srfs_uidbyname("nobody");
//		gid = srfs_uidbyname("nogroup");
//		setegid(gid);
//		seteuid(uid);
//	}
}

char *
srfs_opcode(srfs_opcode_t opcode)
{
	if (opcode >= SRFS_OPCODE_MAX)
		return ("INVALID OPCODE");

	return srfs_opcodes[opcode];
}
