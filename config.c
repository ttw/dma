/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthias Schmidt <matthias@dragonflybsd.org>, University of Marburg,
 * Germany.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "dma.h"
#include "os.h"

#define DP	": \t"
#define EQS	" \t"

static void
chomp(char *str)
{
	size_t len = strlen(str);

	if (len == 0)
		return;
	if (str[len - 1] == '\n')
		str[len - 1] = 0;
}

/*
 * Read the SMTP authentication config file
 *
 * file format is:
 * user|host:password
 *
 * A line starting with # is treated as comment and ignored.
 */
void
parse_authfile(const char *path)
{
	char line[2048];
	struct authuser *au;
	FILE *a;
	char *data;
	int lineno = 0;

	a = fopen(path, "r");
	if (a == NULL) {
		errlog(EX_NOINPUT, "can not open auth file `%s'", path);
		/* NOTREACHED */
	}

	while (!feof(a)) {
		if (fgets(line, sizeof(line), a) == NULL)
			break;
		lineno++;

		chomp(line);

		/* We hit a comment */
		if (*line == '#')
			continue;
		/* Ignore empty lines */
		if (*line == 0)
			continue;

		au = calloc(1, sizeof(*au));
		if (au == NULL)
			errlog(EX_OSERR, NULL);

		data = strdup(line);
		au->login = strsep(&data, "|");
		au->host = strsep(&data, DP);
		au->password = data;

		if (au->login == NULL ||
		    au->host == NULL ||
		    au->password == NULL) {
			errlogx(EX_CONFIG, "syntax error in authfile %s:%d", path, lineno);
			/* NOTREACHED */
		}

		SLIST_INSERT_HEAD(&authusers, au, next);
	}

	fclose(a);
}

const char*
get_mailname( const char *mailname_config )
{
/*[MAN;
.Ss mailname
Return the what we consider to be the correct hostname of the system.  This caches its result and returns the same result after that.  As such, we should set this from the configuration once we are happy.
]*/
			/*[TODO;mailname;
			[ ] refactor conditionals to 'os.h'
			[?] should probably be smarter than just 'gethostname'
				[ ] gethostname > ip address > reverse lookup
			[?] should probably do more checks
				[ ] check TLD hostname (i.e. three parts)
				[ ] getdomainname if not TLD hostname
			[?] mailname check should be part of 'ietf.c'
			[?] should remove 'mailname' from 'err/errx'; redundant restatement of function name (even though it's conceptually the variable name)
			[x] correct sanity check (no '_' in hostnames)
			]*/

	static char *mailname = NULL ;

	int len ;	/* length of mailname */
	char *cp ;	/* generic char pointer */
	int ret ;	/* generic return value */

/* if we've already produced a 'mailname', reuse it */
	if (str_n(mailname))
		return (mailname);
/* ... otherwise, we figure it out. */

/* allocate some memory for 'mailname' */
	len = sysconf(_SC_HOST_NAME_MAX) + 1 ;	/* allow for terminating '\0' */
				/*[TODO; check for '-1']*/
	if (mailname == NULL)
		mailname = (char*)calloc((size_t)len, sizeof(char)) ;	/* include enough for a '\0' terminator */
					/* XXX: will never be free'd (but we're OK with that) */
	if (mailname == NULL)
		err( EXIT_FAILURE, "libc/%s/calloc?mailname", __func__ ) ;

/* prefer the 'config.mailname' configuration ... */
	if (str_n(mailname_config))
	{
		len = snprintf(mailname, len, "%s", mailname_config) ;
					/* ... and crop '\0' from 'len' */
		if( len < 0 )
			errx( EX_SOFTWARE,
					"libc/%s/snprintf?mailname+len=%d",
					__func__,
					len ) ;
	}
/* ... and fallback to 'gethostname' */
	else
	{
		ret = gethostname(mailname, len) ;
		if( ret < 0 )
			err( EXIT_FAILURE, "libc/%s/gethostname?mailname", __func__ ) ;
		if( mailname[len] != '\0' )
			errx( EX_SOFTWARE,
					"libc/%s/gethostname/cropped?mailname+len=%d",
					__func__,
					len ) ;	/* this shouldn't really be possible but 'gethostname' can crop */
	/* find end of 'mailname' */
		while( mailname[len] == '\0' )
			if( --len < 0 )
				errx( EX_SOFTWARE,
					"dma/%s/gethostname?mailname=%s",
					__func__,
					mailname ) ;
	} ;
/* sanity check that mailname chars are 'isalnum' or '-' or '.' ... */
			/*[TODO] need to account for 'locale' (or set it explicitly) */
	for( /*len*/ ; len >= 0 ; len-- )
	{
		if(!isalnum(mailname[len])) break ;
		if(!strchr("-.",mailname[len])) break ;
	} ;
/* ... and as long as we didn't break before start, we're good ... */
	if( len < 0 )
		return (mailname);
/* ... otherwise, we're broke */
	errx( EX_SOFTWARE, "dma/%s?mailname=%s", __func__, mailname ) ;
} ;

/*[TODO;conf.c;
[ ] refactor to remove 'mailname' and use the 'config' option.
[x] need "os.h" for 'synconf' definition
]*/
