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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <security/pam_appl.h>

static char *password = NULL;

static int
checkconv(int num_msg, const struct pam_message **msgs,
	 struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *resps;
	struct pam_response *rsp;
	struct pam_message *msg;

	if (num_msg <= 0)
		return (PAM_CONV_ERR);

	if (!(resps = calloc(num_msg, sizeof(struct pam_response))))
		return (PAM_CONV_ERR);

	for (int i = 0; i < num_msg; i++) {
		msg = (struct pam_message *)msgs[i];
		rsp = &resps[i];
		if (msg->msg_style == PAM_PROMPT_ECHO_OFF)
			rsp->resp = strdup(password);
		rsp->resp_retcode = 0;
	}

	*resp = resps;

	return (PAM_SUCCESS);
}

int
srfs_pam_auth(char *user, char *pass)
{
	struct pam_conv pconv = { checkconv, NULL };
	pam_handle_t *pamh;
	int res;

	password = pass;

	if (pam_start("srfs", user, &pconv, &pamh) != PAM_SUCCESS)
		return (0);

	res = pam_authenticate(pamh, 0);

	pam_end(pamh, res);

	password = NULL;

	return (res == PAM_SUCCESS);
}
