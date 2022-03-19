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

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "srfs_config.h"
#include "srfs_exports.h"

srfs_export_t **exports = NULL;
size_t exportsize = 0;

static void exports_parse_line(char *line, int line_nr, int *exportidx);

static void
exports_parse_line(char *line, int line_nr, int *exportidx)
{
	size_t newsize, clrsize;
	srfs_export_t *export;
	char *share;
	char *localdir;
	char *t;
	int i;

	for (i = 0, t = strtok(line, " \t"); t; t = strtok(NULL, " \t"), i++) {
		if  (t[0] == '#')
			break;
		if  (t[0] == '\n')
			break;
		if (i >= 2) {
			printf("ignoring invalid exports line %d\n", line_nr);
			return;
		}

		if (i == 0) share = t;
		if (i == 1) localdir = t;
	}

	if (i == 2) {
		export = malloc(sizeof(srfs_export_t));
		export->share = share;
		export->localdir = localdir;

		if (*exportidx == exportsize) {
			exportsize += 10;
			newsize = sizeof(srfs_export_t *) * exportsize;
			clrsize = sizeof(srfs_export_t *) * 10;
			exports = realloc(exports, newsize);
			bzero(exports + (exportsize - 10), clrsize);
		}

		exports[*exportidx] = export;
		exportidx[0]++;
	}
}

void
srfs_exports_load(void)
{
	char buf[1024];
	int exportidx;
	int line_nr;
	FILE *f;

	if (!(f = fopen(SRFS_EXPORTS_FILE, "r"))) {
		if (!exports) {
			err(errno, "Couldn't open %s", SRFS_EXPORTS_FILE);
		}
		return;
	}

	if (exports) {
		for (int i = 0; exports[i]; i++)
			free(exports[i]);
		free(exports);
	}

	exportidx = 0;
	exportsize = 10;
	exports = calloc(1, sizeof(srfs_export_t *) * exportsize);

	for (line_nr = 0; fgets(buf, 1024, f); line_nr++)
		exports_parse_line(buf, line_nr, &exportidx);

	fclose(f);
}

srfs_export_t *
srfs_export_by_sharename(char *share)
{
	for (int i = 0; exports[i]; i++)
		if (strcmp(exports[i]->share, share) == 0)
			return (exports[i]);

	return (NULL);
}
