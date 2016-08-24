/*
 * Copyright (c) 2008-2014, Simon Schubert <2@0x2c.org>.
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Simon Schubert <2@0x2c.org> and
 * Matthias Schmidt <matthias@dragonflybsd.org>.
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

#ifndef DMA_H
#define DMA_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include <sysexits.h>

#define VERSION	"DragonFly Mail Agent " DMA_VERSION

#define BUF_SIZE	2048
#define ERRMSG_SIZE	1024
#define USERNAME_SIZE	50
#define MIN_RETRY	300		/* 5 minutes */
#define MAX_RETRY	(3*60*60)	/* retry at least every 3 hours */
#define MAX_TIMEOUT	(5*24*60*60)	/* give up after 5 days */
#define SLEEP_TIMEOUT	30		/* check for queue flush every 30 seconds */
#define RFC2822_LINE_MAX	1000		/* Max email line length, per RFC2822 */
#define DMA_LINE_MAX	65536		/* Max email line length, internal */
#define	SMTP_PORT	25		/* Default SMTP port */
#define CON_TIMEOUT	(5*60)		/* Connection timeout per RFC5321 */

#define SPOOL_FLUSHFILE	"flush"

#define str_z(x) (x == NULL || *x == '\0')
#define str_n(x) (!str_z(x))

struct qitem {
	LIST_ENTRY(qitem) next;
	const char *sender;
	char *addr;
	char *queuefn;
	char *mailfn;
	char *queueid;
	FILE *queuef;
	FILE *mailf;
	int remote;
};
LIST_HEAD(queueh, qitem);

struct queue {
	struct queueh queue;
	char *id;
	FILE *mailf;
	char *tmpf;
	const char *sender;
};

struct authuser {
	SLIST_ENTRY(authuser) next;
	char *login;
	char *password;
	char *host;
};
SLIST_HEAD(authusers, authuser);


/* global variables */
extern struct aliases aliases;
extern struct config config;
extern struct strlist tmpfs;
extern struct authusers authusers;
extern char username[USERNAME_SIZE];
extern uid_t useruid;
extern const char *logident_base;

extern char neterr[ERRMSG_SIZE];
extern char errmsg[ERRMSG_SIZE];

/* conf.c */
void trim_line(char *);
void parse_conf(const char *);
void parse_authfile(const char *);

/* base64.c */
int base64_encode(const void *, int, char **);
int base64_decode(const char *, void *);

/* dma.c */
int add_recp(struct queue *, const char *, int);
#define ADD_RECP_NO_EXPAND 0
#define ADD_RECP_EXPAND 1
#define ADD_RECP_EXPAND_WILDCARD 2
void run_queue(struct queue *);

/* spool.c */
int newspoolf(struct queue *);
int linkspool(struct queue *);
int load_queue(struct queue *);
void delqueue(struct qitem *);
int acquirespool(struct qitem *);
void dropspool(struct queue *, struct qitem *);
int flushqueue_since(unsigned int);
int flushqueue_signal(void);

/* local.c */
int deliver_local(struct qitem *);

/* mail.c */
void bounce(struct qitem *, const char *);
int readmail(struct queue *, int, int);

/* util.c */
const char *hostname(void);
void setlogident(const char *, ...) __attribute__((__format__ (__printf__, 1, 2)));
void errlog(int, const char *, ...) __attribute__((__format__ (__printf__, 2, 3)));
void errlogx(int, const char *, ...) __attribute__((__format__ (__printf__, 2, 3)));
void set_username(void);
void deltmp(void);
int do_timeout(int, int);
int open_locked(const char *, int, ...);
char *rfc822date(void);
int strprefixcmp(const char *, const char *);
void init_random(void);

#endif

/*[TODO;
[ ] don't like how the header definitions are collected here; makes for simple include directives but breaks explict dependencies; prefer to be conservative and explicit with these.
[x] define 'str' functions for empty and not empty (not sure I like my naming convetion here?)
]*/
