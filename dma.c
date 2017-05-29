/*
 * Copyright (c) 2008-2014, Simon Schubert <2@0x2c.org>.
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Simon Schubert <2@0x2c.org>.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "aliases.h"
#include "dma.h"
#include "conf.h"
#include "net.h"

char _os_progname[PATH_MAX] = {0} ;

static void
sighup_handler(int signo)
{
	(void)signo;	/* so that gcc doesn't complain */
}

static char *
set_from(struct queue *queue, const char *osender)
{
	const char *addr;
	char *sender;

	if (osender) {
		addr = osender;
	} else if (getenv("EMAIL") != NULL) {
		addr = getenv("EMAIL");
	} else {
		if (config.masquerade_user)
			addr = config.masquerade_user;
		else
			addr = username;
	}

	if (!strchr(addr, '@')) {
		const char *from_host = mailname();

		if (config.masquerade_host)
			from_host = config.masquerade_host;

		if (asprintf(&sender, "%s@%s", addr, from_host) <= 0)
			return (NULL);
	} else {
		sender = strdup(addr);
		if (sender == NULL)
			return (NULL);
	}

	if (strchr(sender, '\n') != NULL) {
		errno = EINVAL;
		return (NULL);
	}

	queue->sender = sender;
	return (sender);
}

static int
read_aliases(void)
{
	yyin = fopen(config.aliases, "r");
	if (yyin == NULL) {
		/*
		 * Non-existing aliases file is not a fatal error
		 */
		if (errno == ENOENT)
			return (0);
		/* Other problems are. */
		return (-1);
	}
	if (yyparse())
		return (-1);	/* fatal error, probably malloc() */
	fclose(yyin);
	return (0);
}

static int
do_alias(struct queue *queue, const char *addr)
{
	struct alias *al;
        struct stritem *sit;
	int aliased = 0;

        LIST_FOREACH(al, &aliases, next) {
                if (strcmp(al->alias, addr) != 0)
                        continue;
		SLIST_FOREACH(sit, &al->dests, next) {
			if (add_recp(queue, sit->str, ADD_RECP_EXPAND) != 0)
				return (-1);
		}
		aliased = 1;
        }

        return (aliased);
}

int
add_recp(struct queue *queue, const char *str, int expand)
{
	struct qitem *it, *tit;
	struct passwd *pw;
	char *host;
	int aliased = 0;

	it = calloc(1, sizeof(*it));
	if (it == NULL)
		return (-1);
	it->addr = strdup(str);
	if (it->addr == NULL)
		return (-1);

	it->sender = queue->sender;
	host = strrchr(it->addr, '@');
	if (host != NULL &&
	    (strcmp(host + 1, mailname()) == 0 ||
	     strcmp(host + 1, "localhost") == 0)) {
		*host = 0;
	}
	LIST_FOREACH(tit, &queue->queue, next) {
		/* weed out duplicate dests */
		if (strcmp(tit->addr, it->addr) == 0) {
			free(it->addr);
			free(it);
			return (0);
		}
	}
	LIST_INSERT_HEAD(&queue->queue, it, next);

	/**
	 * Do local delivery if there is no @.
	 * Do not do local delivery when NULLCLIENT is set.
	 */
	if (strrchr(it->addr, '@') == NULL && (config.features & NULLCLIENT) == 0) {
		it->remote = 0;
		if (expand) {
			aliased = do_alias(queue, it->addr);
			if (!aliased && expand == ADD_RECP_EXPAND_WILDCARD)
				aliased = do_alias(queue, "*");
			if (aliased < 0)
				return (-1);
			if (aliased) {
				LIST_REMOVE(it, next);
			} else {
				/* Local destination, check */
				pw = getpwnam(it->addr);
				if (pw == NULL)
					goto out;
				/* XXX read .forward */
				endpwent();
			}
		}
	} else {
		it->remote = 1;
	}

	return (0);

out:
	free(it->addr);
	free(it);
	return (-1);
}

static struct qitem *
go_background(struct queue *queue)
{
	struct sigaction sa;
	struct qitem *it;
	pid_t pid;

	if (daemonize && daemon(0, 0) != 0) {
		syslog(LOG_ERR, "can not daemonize: %m");
		exit(EX_OSERR);
	}
	daemonize = 0;

	bzero(&sa, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);

	LIST_FOREACH(it, &queue->queue, next) {
		/* No need to fork for the last dest */
		if (LIST_NEXT(it, next) == NULL)
			goto retit;

		pid = fork();
		switch (pid) {
		case -1:
			syslog(LOG_ERR, "can not fork: %m");
			exit(EX_OSERR);
			break;

		case 0:
			/*
			 * Child:
			 *
			 * return and deliver mail
			 */
retit:
			/*
			 * If necessary, acquire the queue and * mail files.
			 * If this fails, we probably were raced by another
			 * process.  It is okay to be raced if we're supposed
			 * to flush the queue.
			 */
			setlogident("%s", it->queueid);
			switch (acquirespool(it)) {
			case 0:
				break;
			case 1:
				if (doqueue)
					exit(EX_OK);
				syslog(LOG_WARNING, "could not lock queue file");
				exit(EX_SOFTWARE);
			default:
				exit(EX_SOFTWARE);
			}
			dropspool(queue, it);
			return (it);

		default:
			/*
			 * Parent:
			 *
			 * fork next child
			 */
			break;
		}
	}

	syslog(LOG_CRIT, "reached dead code");
	exit(EX_SOFTWARE);
}

static void
deliver(struct qitem *it)
{
	int error;
	unsigned int backoff = MIN_RETRY, slept;
	struct timeval now;
	struct stat st;

	snprintf(errmsg, sizeof(errmsg), "unknown bounce reason");

retry:
	syslog(LOG_INFO, "<%s> trying delivery", it->addr);

	if (it->remote)
		error = deliver_remote(it);
	else
		error = deliver_local(it);

	switch (error) {
	case 0:
		delqueue(it);
		syslog(LOG_INFO, "<%s> delivery successful", it->addr);
		exit(EX_OK);

	case 1:
		if (stat(it->queuefn, &st) != 0) {
			syslog(LOG_ERR, "lost queue file `%s'", it->queuefn);
			exit(EX_SOFTWARE);
		}
		if (gettimeofday(&now, NULL) == 0 &&
		    (now.tv_sec - st.st_mtim.tv_sec > MAX_TIMEOUT)) {
			snprintf(errmsg, sizeof(errmsg),
				 "Could not deliver for the last %d seconds. Giving up.",
				 MAX_TIMEOUT);
			goto bounce;
		}
		for (slept = 0; slept < backoff;) {
			slept += SLEEP_TIMEOUT - sleep(SLEEP_TIMEOUT);
			if (flushqueue_since(slept)) {
				backoff = MIN_RETRY;
				goto retry;
			}
		}
		if (slept >= backoff) {
			/* pick the next backoff between [1.5, 2.5) times backoff */
			backoff = backoff + backoff / 2 + random() % backoff;
			if (backoff > MAX_RETRY)
				backoff = MAX_RETRY;
		}
		goto retry;

	case -1:
	default:
		break;
	}

bounce:
	bounce(it, errmsg);
	/* NOTREACHED */
}

void
run_queue(struct queue *queue)
{
	struct qitem *it;

	if (LIST_EMPTY(&queue->queue))
		return;

	it = go_background(queue);
	deliver(it);
	/* NOTREACHED */
}

static void
show_queue(struct queue *queue)
{
	struct qitem *it;
	int locked = 0;	/* XXX */

	if (LIST_EMPTY(&queue->queue)) {
		printf("Mail queue is empty\n");
		return;
	}

	LIST_FOREACH(it, &queue->queue, next) {
		printf("ID\t: %s%s\n"
		       "From\t: %s\n"
		       "To\t: %s\n",
		       it->queueid,
		       locked ? "*" : "",
		       it->sender, it->addr);

		if (LIST_NEXT(it, next) != NULL)
			printf("--\n");
	}
}

/*
sendmail options
	-Ac	=> ignore
	-Am	=> ignore

	-bp	=> mailq mode
	-bP	=> print queue length
	-bm	=> normal delivery
	-bi	=> ignore

	-bs	=> [?] implement this
	-*	=> abort

	-d*.*	=> foreground / debugging; level ignored
				[ ] approx. map to 'dma' debugging levels

	-F	=> fullname
	-f	=> name

	-i	=> ignore dots

	-OIgnoreDots	=> same as '-i'
	-oi		=> same as '-i'
	-O*		=> abort
	-o*		=> abort

	-q[arg]		=> queue run (wait 'arg' time)

	-r:name	=> same as '-f'

	-t	=> recipients from message
*/

enum DMA_MODE
{
	DMA_MODE_MAIL,
	DMA_MODE_QUEUE,
	DMA_MODE_MAX
} ;

enum DMA_MODE_MAIL_OPTS
{
	DMA_MAIL_DELIVER,	/* default */
	DMA_MAIL_DEFERRED,	/* FEATURE_DEFER */
	DMA_MAIL_DELIVER_REMOTE,	/* FEATURE_NULLCLIENT */
	DMA_MODE_MAIL_OPTS_MAX
} ;

enum DMA_MODE_QUEUE_OPTS
{
	DMA_QUEUE_RUN,
	DMA_QUEUE_PRINT,
	DMA_QUEUE_COUNT,
	DMA_MODE_QUEUE_OPTS_MAX
} ;

enum DMA_FEATURE
{
	DMA_MAIL_BOUNCE_MSG	/* FEATURE_FULLBOUNCE */
	DMA_MASQUERADE
} ;

enum DMA_TRANSPORT
{
	DMA_TRANSPORT_AUTH,
	DMA_TRANSPORT_ENC,
	DMA_TRANSPORT_MAX
} ;

enum DMA_TRANSPORT_AUTH_OPT
{
	DMA_TRANSPORT_AUTH_MD5,	/* FEATURE_SECURE */
	DMA_TRANSPORT_AUTH_PLAIN,	/* FEATURE_INSECURE */
} ;

enum DMA_TRANSPORT_ENC_OPT
{
	DMA_TRANSPORT_ENC_NONE,	/* default */
	DMA_TRANSPORT_ENC_SSL,	/* FEATURE_SECURETRANS */
	DMA_TRANSPORT_ENC_TLS, /* FEATURE_STARTTLS */
	DMA_TRANSPORT_ENC_TLS_OPT /* FEATURE_TLS_OPP */
} ;

struct dma
{
	int mode[DMA_MODE_MAX] ;	/* see DMA_MODE */
	int debug ;	/* > 0 = foreground */
	char *ident ;	/* for 'syslog' */

	struct aliases_list *aliases ;

        const char *mailname ;
        const char *masquerade ;

        const char *smarthost ;	/* [ ] convert to useful structure here */
        const char *port ;	/* [ ] merge with smarthost */

	const char *spool_dir ; /* [?] see todo */
} ;

/* DMA OPTIONS

-d	foreground
-D	DMA_MAIL_DEFERRED

-f from
-i
-l ident

-n	DMA_QUEUE_COUNT
-p	DMA_QUEUE_PRINT
-q	DMA_QUEUE_RUN

-t	
-v	verbosity

*/

enum DMA_MAIL_OPTS
{
	DMA_MAIL_OPT_RECP_FROM_MSG,	/* -t */
	DMA_MAIL_OPT_MSG_FROM_FILE,	/* -i */
	DMA_MAIL_OPT_MAX
} ;

struct dma_addr
{
	char *_addr ;	/* string base (free'd if changed) */
	char *local ;	/* '-f' or 'EMAIL' environment */
	char *at ;
	char *domain ;	/* 
	char *addr_display ;	/* '-F' */
} ;

struct dma_mail
{
	char *from ;	/* '-f' or 'EMAIL' and '-F' */
	struc recp_list to ;
	struct recp_list cc ;
	struct recp_list bcc ;
	int opts[DMA_MAIL_OPT_MAX] ;
} ;

int
main(int argc, char **argv)
{
	struct config config ;
	struct sigaction act;
	char *sender = NULL;
	struct queue queue;
	int i, ch;
	int nodot = 0, showq = 0, queue_only = 0;
	int recp_from_header = 0;
	size_t sz ;

	sz = strlcpy( _os_progname, getprogname(), sizeof(_os_progname) ) ;
	if(sz == 0) setprogname(argv[0]) ;
				/*[TODO; [ ] modify progname so we know 'sendmail' is actually 'dma' ]*/

	if (geteuid() == 0 || getuid() == 0) {
	/* drop privilage; switch to DMA_USER */
		struct passwd *pw;

		errno = 0;
		pw = getpwnam(DMA_USER);
		if (pw == NULL) {
			if (errno == 0)
				errx(EX_CONFIG, "user '%s' not found", DMA_USER);
			else
				err(EX_OSERR, "cannot drop root privileges");
		}

		if (setuid(pw->pw_uid) != 0)
			err(EX_OSERR, "cannot drop root privileges");

		if (geteuid() == 0 || getuid() == 0)
			errx(EX_OSERR, "cannot drop root privileges");
	}

	atexit(deltmp);
	init_random();

	bzero(&queue, sizeof(queue));
	LIST_INIT(&queue.queue);

	if (strcmp(argv[0], "mailq") == 0) {
		argv++; argc--;
		showq = 1;
		if (argc != 0)
			errx(EX_USAGE, "invalid arguments");
		goto skipopts;
	} else if (strcmp(argv[0], "newaliases") == 0) {
		logident_base = "dma";
		setlogident(NULL);

		if (read_aliases() != 0)
			errx(EX_SOFTWARE, "could not parse aliases file `%s'", config.aliases);
		exit(EX_OK);
	}

	opterr = 0;
	while ((ch = getopt(argc, argv, ":A:b:B:C:d:Df:F:h:iL:N:no:O:q:r:R:tUV:vX:")) != -1) {
		switch (ch) {
		case 'A':
			/* -AX is being ignored, except for -A{c,m} */
			if (optarg[0] == 'c' || optarg[0] == 'm') {
				break;
			}
			/* else FALLTRHOUGH */
		case 'b':
			/* -bX is being ignored, except for -bp */
			if (optarg[0] == 'p') {
				showq = 1;
				break;
			} else if (optarg[0] == 'q') {
				queue_only = 1;
				break;
			}
			/* else FALLTRHOUGH */
		case 'D':
			daemonize = 0;
			break;
		case 'L':
			logident_base = optarg;
			break;
		case 'f':
		case 'r':
			sender = optarg;
			break;

		case 't':
			recp_from_header = 1;
			break;

		case 'o':
			/* -oX is being ignored, except for -oi */
			if (optarg[0] != 'i')
				break;
			/* else FALLTRHOUGH */
		case 'O':
			break;
		case 'i':
			nodot = 1;
			break;

		case 'q':
			/* Don't let getopt slup up other arguments */
			if (optarg && *optarg == '-')
				optind--;
			doqueue = 1;
			break;

		/* Ignored options */
		case 'B':
		case 'C':
		case 'd':
		case 'F':
		case 'h':
		case 'N':
		case 'n':
		case 'R':
		case 'U':
		case 'V':
		case 'v':
		case 'X':
			break;

		case ':':
			if (optopt == 'q') {
				doqueue = 1;
				break;
			}
			/* FALLTHROUGH */

		default:
			fprintf(stderr, "invalid argument: `-%c'\n", optopt);
			exit(EX_USAGE);
		}
	}
	argc -= optind;
	argv += optind;
	opterr = 1;

	if (argc != 0 && (showq || doqueue))
		errx(EX_USAGE, "sending mail and queue operations are mutually exclusive");

	if (showq + doqueue > 1)
		errx(EX_USAGE, "conflicting queue operations");

skipopts:
	if (logident_base == NULL)
		logident_base = "dma";
	setlogident(NULL);

	act.sa_handler = sighup_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGHUP, &act, NULL) != 0)
		syslog(LOG_WARNING, "can not set signal handler: %m");

	parse_conf(DMA_CONF_PATH);

	if (config.authpath != NULL)
		parse_authfile(config.authpath);

	if (showq) {
		if (load_queue(&queue) < 0)
			errlog(EX_NOINPUT, "can not load queue");
		show_queue(&queue);
		return (0);
	}

	if (doqueue) {
		flushqueue_signal();
		if (load_queue(&queue) < 0)
			errlog(EX_NOINPUT, "can not load queue");
		run_queue(&queue);
		return (0);
	}

	if (read_aliases() != 0)
		errlog(EX_SOFTWARE, "could not parse aliases file `%s'", config.aliases);

	if ((sender = set_from(&queue, sender)) == NULL)
		errlog(EX_SOFTWARE, NULL);

	if (newspoolf(&queue) != 0)
		errlog(EX_CANTCREAT, "can not create temp file in `%s'", config.spooldir);

	setlogident("%s", queue.id);

	for (i = 0; i < argc; i++) {
		if (add_recp(&queue, argv[i], ADD_RECP_EXPAND_WILDCARD) != 0)
			errlogx(EX_DATAERR, "invalid recipient `%s'", argv[i]);
	}

	if (LIST_EMPTY(&queue.queue) && !recp_from_header)
		errlogx(EX_NOINPUT, "no recipients");

	if (readmail(&queue, nodot, recp_from_header) != 0)
		errlog(EX_NOINPUT, "can not read mail");

	if (LIST_EMPTY(&queue.queue))
		errlogx(EX_NOINPUT, "no recipients");

	if (linkspool(&queue) != 0)
		errlog(EX_CANTCREAT, "can not create spools");

	/* From here on the mail is safe. */

	if (config.features & DEFER || queue_only)
		return (0);

	run_queue(&queue);

	/* NOTREACHED */
	return (0);
}

/*[TODO;
[x] change paths to [Makefile] variables
[x] correct EXPAND mis-define
[x] switch from 'hostname' to 'mailname'
[ ] use a standard 'conf' format and then create a library for it
[ ] alias processing
[ ] use group permissions
[ ] proper sysexit codes
[?] 'spooldir' as local or global
			obviously this makes more sense as a global variable but perhaps I will hold-on to the idea that users might have their own spool queues.
[x] change '-bq'; unnecessarily confused with sendmail like options
]*/
