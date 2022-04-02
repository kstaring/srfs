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

#ifndef _SRFS_USRGRP_H
#define _SRFS_USRGRP_H

#include <pwd.h>
#include <grp.h>

extern void srfs_usrgrp_init(void);

extern char *srfs_namebyuid(uid_t uid);
extern uid_t srfs_uidbyname(char *usrname);

extern char *srfs_namebygid(gid_t gid);
extern uid_t srfs_gidbyname(char *grpname);

extern void srfs_usrconv_set(char *lcl_usr, char *rmt_usr);
extern char *srfs_usrconv(char *usrname);

extern char *srfs_homebyuid(uid_t uid);
extern gid_t srfs_gidbyuid(uid_t uid);

extern int srfs_usrisnobody(char *usrname);

extern void sfrs_set_authenticated(char *usrname);
extern int srfs_usr_authenticated(char *usrname);
extern int srfs_uid_authenticated(uid_t uid);
extern void srfs_flush_auth(void);

#endif
