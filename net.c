/*
 * Copyright (c) 2008-2014, Simon Schubert <2@0x2c.org>.
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

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <resolv.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "net.h"
#include "conf.h"

struct
mx_hostentry
{
	char host[MAXDNAME] ;
	char addr[INET6_ADDRSTRLEN] ;
	int pref ;
	struct addrinfo ai ;
	struct sockaddr_storage sa ;
} ;

static int add_host( int, const char*, int, struct mx_hostentry**, size_t* ) ;

static void close_connection( int ) ;

static int deliver_to_host( struct qitem*, struct mx_hostentry* ) ;

static int get_mx_list( const char*, int, struct mx_hostentry**, int ) ;

static void hmac_md5( unsigned char*, int, unsigned char*, int, unsigned char* ) ;

static int init_cert_file( SSL_CTX*, const char*) ;

static int open_connection( struct mx_hostentry* ) ;

static int read_remote( int, int, char* ) ;

static ssize_t send_remote_command( int, const char*, ...) ;

static int smtp_auth_md5( int, char*, char* ) ;

static int smtp_init_crypto( int, int ) ;

static int smtp_login( int, char*, char* ) ;

static int sort_pref( const void*, const void* ) ;

static char* ssl_errstr() ;

/* global definitions */
char neterr[ERRMSG_SIZE];

/* base64.c defines */
int base64_encode(const void *, int, char **);

static char *
ssl_errstr(void)
{
	long oerr, nerr;

	oerr = 0;
	while ((nerr = ERR_get_error()) != 0)
		oerr = nerr;

	return (ERR_error_string(oerr, NULL));
}

int
deliver_remote(struct qitem *it)
{
	struct mx_hostentry *hosts, *h;
	const char *host;
	int port;
	int error = 1, smarthost = 0;

	port = SMTP_PORT;

	/* Smarthost support? */
	if (config.smarthost != NULL) {
		host = config.smarthost;
		port = config.port;
		syslog(LOG_INFO, "using smarthost (%s:%i)", host, port);
		smarthost = 1;
	} else {
		host = strrchr(it->addr, '@');
		/* Should not happen */
		if (host == NULL) {
			snprintf(errmsg, sizeof(errmsg), "Internal error: badly formed address %s",
				 it->addr);
			return(-1);
		} else {
			/* Step over the @ */
			host++;
		}
	}

	error = get_mx_list(host, port, &hosts, smarthost);
	if (error) {
		snprintf(errmsg, sizeof(errmsg), "DNS lookup failure: host %s not found", host);
		syslog(LOG_NOTICE, "remote delivery %s: DNS lookup failure: host %s not found",
		       error < 0 ? "failed" : "deferred",
		       host);
		return (error);
	}

	for (h = hosts; *h->host != 0; h++) {
		switch (deliver_to_host(it, h)) {
		case 0:
			/* success */
			error = 0;
			goto out;
		case 1:
			/* temp failure */
			error = 1;
			break;
		default:
			/* perm failure */
			error = -1;
			goto out;
		}
	}
out:
	free(hosts);

	return (error);
}

static int
read_remote(int fd, int extbufsize, char *extbuf)
{
	ssize_t rlen = 0;
	size_t pos, len, copysize;
	char buff[BUF_SIZE];
	int done = 0, status = 0, status_running = 0, extbufpos = 0;
	enum { parse_status, parse_spacedash, parse_rest } parsestate;

	if (do_timeout(CON_TIMEOUT, 1) != 0) {
		snprintf(neterr, sizeof(neterr), "Timeout reached");
		return (-1);
	}

	/*
	 * Remote reading code from femail.c written by Henning Brauer of
	 * OpenBSD and released under a BSD style license.
	 */
	len = 0;
	pos = 0;
	parsestate = parse_status;
	neterr[0] = 0;
	while (!(done && parsestate == parse_status)) {
		rlen = 0;
		if (pos == 0 ||
		    (pos > 0 && memchr(buff + pos, '\n', len - pos) == NULL)) {
			memmove(buff, buff + pos, len - pos);
			len -= pos;
			pos = 0;
			if (((config.features & SECURETRANS) != 0) &&
			    (config.features & NOSSL) == 0) {
				if ((rlen = SSL_read(config.ssl, buff + len, sizeof(buff) - len)) == -1) {
					strncpy(neterr, ssl_errstr(), sizeof(neterr));
					goto error;
				}
			} else {
				if ((rlen = read(fd, buff + len, sizeof(buff) - len)) == -1) {
					strncpy(neterr, strerror(errno), sizeof(neterr));
					goto error;
				}
			}
			len += rlen;

			copysize = sizeof(neterr) - strlen(neterr) - 1;
			if (copysize > len)
				copysize = len;
			strncat(neterr, buff, copysize);
		}
		/*
		 * If there is an external buffer with a size bigger than zero
		 * and as long as there is space in the external buffer and
		 * there are new characters read from the mailserver
		 * copy them to the external buffer
		 */
		if (extbufpos <= (extbufsize - 1) && rlen > 0 && extbufsize > 0 && extbuf != NULL) {
			/* do not write over the bounds of the buffer */
			if(extbufpos + rlen > (extbufsize - 1)) {
				rlen = extbufsize - extbufpos;
			}
			memcpy(extbuf + extbufpos, buff + len - rlen, rlen);
			extbufpos += rlen;
		}

		if (pos == len)
			continue;

		switch (parsestate) {
		case parse_status:
			for (; pos < len; pos++) {
				if (isdigit(buff[pos])) {
					status_running = status_running * 10 + (buff[pos] - '0');
				} else {
					status = status_running;
					status_running = 0;
					parsestate = parse_spacedash;
					break;
				}
			}
			continue;

		case parse_spacedash:
			switch (buff[pos]) {
			case ' ':
				done = 1;
				break;

			case '-':
				/* ignore */
				/* XXX read capabilities */
				break;

			default:
				strcpy(neterr, "invalid syntax in reply from server");
				goto error;
			}

			pos++;
			parsestate = parse_rest;
			continue;

		case parse_rest:
			/* skip up to \n */
			for (; pos < len; pos++) {
				if (buff[pos] == '\n') {
					pos++;
					parsestate = parse_status;
					break;
				}
			}
		}

	}

	do_timeout(0, 0);

	/* chop off trailing newlines */
	while (neterr[0] != 0 && strchr("\r\n", neterr[strlen(neterr) - 1]) != 0)
		neterr[strlen(neterr) - 1] = 0;

	return (status/100);

error:
	do_timeout(0, 0);
	return (-1);
}

static ssize_t
send_remote_command(int fd, const char* fmt, ...)
{
	va_list va;
	char cmd[4096];
	size_t len, pos;
	int s;
	ssize_t n;

	va_start(va, fmt);
	s = vsnprintf(cmd, sizeof(cmd) - 2, fmt, va);
	va_end(va);
	if (s == sizeof(cmd) - 2 || s < 0) {
		strcpy(neterr, "Internal error: oversized command string");
		return (-1);
	}

	/* We *know* there are at least two more bytes available */
	strcat(cmd, "\r\n");
	len = strlen(cmd);

	if (((config.features & SECURETRANS) != 0) &&
	    ((config.features & NOSSL) == 0)) {
		while ((s = SSL_write(config.ssl, (const char*)cmd, len)) <= 0) {
			s = SSL_get_error(config.ssl, s);
			if (s != SSL_ERROR_WANT_READ &&
			    s != SSL_ERROR_WANT_WRITE) {
				strncpy(neterr, ssl_errstr(), sizeof(neterr));
				return (-1);
			}
		}
	}
	else {
		pos = 0;
		while (pos < len) {
			n = write(fd, cmd + pos, len - pos);
			if (n < 0)
				return (-1);
			pos += n;
		}
	}

	return (len);
}

/*
 * Handle SMTP authentication
 */
static int
smtp_login(int fd, char *login, char* password)
{
	char *temp;
	int len, res = 0;

	res = smtp_auth_md5(fd, login, password);
	if (res == 0) {
		return (0);
	} else if (res == -2) {
	/*
	 * If the return code is -2, then then the login attempt failed,
	 * do not try other login mechanisms
	 */
		return (1);
	}

	if ((config.features & INSECURE) != 0 ||
	    (config.features & SECURETRANS) != 0) {
		/* Send AUTH command according to RFC 2554 */
		send_remote_command(fd, "AUTH LOGIN");
		if (read_remote(fd, 0, NULL) != 3) {
			syslog(LOG_NOTICE, "remote delivery deferred:"
					" AUTH login not available: %s",
					neterr);
			return (1);
		}

		len = base64_encode(login, strlen(login), &temp);
		if (len < 0) {
encerr:
			syslog(LOG_ERR, "can not encode auth reply: %m");
			return (1);
		}

		send_remote_command(fd, "%s", temp);
		free(temp);
		res = read_remote(fd, 0, NULL);
		if (res != 3) {
			syslog(LOG_NOTICE, "remote delivery %s: AUTH login failed: %s",
			       res == 5 ? "failed" : "deferred", neterr);
			return (res == 5 ? -1 : 1);
		}

		len = base64_encode(password, strlen(password), &temp);
		if (len < 0)
			goto encerr;

		send_remote_command(fd, "%s", temp);
		free(temp);
		res = read_remote(fd, 0, NULL);
		if (res != 2) {
			syslog(LOG_NOTICE, "remote delivery %s: Authentication failed: %s",
					res == 5 ? "failed" : "deferred", neterr);
			return (res == 5 ? -1 : 1);
		}
	} else {
		syslog(LOG_WARNING, "non-encrypted SMTP login is disabled in config, so skipping it. ");
		return (1);
	}

	return (0);
}

static int
open_connection(struct mx_hostentry *h)
{
	int fd;

	syslog(LOG_INFO, "trying remote delivery to %s [%s] pref %d",
	       h->host, h->addr, h->pref);

	fd = socket(h->ai.ai_family, h->ai.ai_socktype, h->ai.ai_protocol);
	if (fd < 0) {
		syslog(LOG_INFO, "socket for %s [%s] failed: %m",
		       h->host, h->addr);
		return (-1);
	}

	if (connect(fd, (struct sockaddr *)&h->sa, h->ai.ai_addrlen) < 0) {
		syslog(LOG_INFO, "connect to %s [%s] failed: %m",
		       h->host, h->addr);
		close(fd);
		return (-1);
	}

	return (fd);
}

static void
close_connection(int fd)
{
	if (config.ssl != NULL) {
		if (((config.features & SECURETRANS) != 0) &&
		    ((config.features & NOSSL) == 0))
			SSL_shutdown(config.ssl);
		SSL_free(config.ssl);
	}

	close(fd);
}

static int
deliver_to_host(struct qitem *it, struct mx_hostentry *host)
{
	struct authuser *a;
	char line[RFC2822_LINE_MAX];
	size_t linelen;
	int fd, error = 0, do_auth = 0, res = 0;

	if (fseek(it->mailf, 0, SEEK_SET) != 0) {
		snprintf(errmsg, sizeof(errmsg), "can not seek: %s", strerror(errno));
		return (-1);
	}

	fd = open_connection(host);
	if (fd < 0)
		return (1);

#define READ_REMOTE_CHECK(c, exp)	\
	res = read_remote(fd, 0, NULL); \
	if (res == 5) { \
		syslog(LOG_ERR, "remote delivery to %s [%s] failed after %s: %s", \
		       host->host, host->addr, c, neterr); \
		snprintf(errmsg, sizeof(errmsg), "%s [%s] did not like our %s:\n%s", \
			 host->host, host->addr, c, neterr); \
		error = -1; \
		goto out; \
	} else if (res != exp) { \
		syslog(LOG_NOTICE, "remote delivery deferred: %s [%s] failed after %s: %s", \
		       host->host, host->addr, c, neterr); \
		error = 1; \
		goto out; \
	}

	/* Check first reply from remote host */
	if ((config.features & SECURETRANS) == 0 ||
	    (config.features & STARTTLS) != 0) {
		config.features |= NOSSL;
		READ_REMOTE_CHECK("connect", 2);

		config.features &= ~NOSSL;
	}

	if ((config.features & SECURETRANS) != 0) {
		error = smtp_init_crypto(fd, config.features);
		if (error == 0)
			syslog(LOG_DEBUG, "SSL initialization successful");
		else
			goto out;

		if ((config.features & STARTTLS) == 0)
			READ_REMOTE_CHECK("connect", 2);
	}

	/* XXX allow HELO fallback */
	/* XXX record ESMTP keywords */
	send_remote_command(fd, "EHLO %s", mailname());
	READ_REMOTE_CHECK("EHLO", 2);

	/*
	 * Use SMTP authentication if the user defined an entry for the remote
	 * or smarthost
	 */
	SLIST_FOREACH(a, &authusers, next) {
		if (strcmp(a->host, host->host) == 0) {
			do_auth = 1;
			break;
		}
	}

	if (do_auth == 1) {
		/*
		 * Check if the user wants plain text login without using
		 * encryption.
		 */
		syslog(LOG_INFO, "using SMTP authentication for user %s", a->login);
		error = smtp_login(fd, a->login, a->password);
		if (error < 0) {
			syslog(LOG_ERR, "remote delivery failed:"
					" SMTP login failed: %m");
			snprintf(errmsg, sizeof(errmsg), "SMTP login to %s failed", host->host);
			error = -1;
			goto out;
		}
		/* SMTP login is not available, so try without */
		else if (error > 0) {
			syslog(LOG_WARNING, "SMTP login not available. Trying without.");
		}
	}

	/* XXX send ESMTP ENVID, RET (FULL/HDRS) and 8BITMIME */
	send_remote_command(fd, "MAIL FROM:<%s>", it->sender);
	READ_REMOTE_CHECK("MAIL FROM", 2);

	/* XXX send ESMTP ORCPT */
	send_remote_command(fd, "RCPT TO:<%s>", it->addr);
	READ_REMOTE_CHECK("RCPT TO", 2);

	send_remote_command(fd, "DATA");
	READ_REMOTE_CHECK("DATA", 3);

	error = 0;
	while (!feof(it->mailf)) {
		if (fgets(line, sizeof(line), it->mailf) == NULL)
			break;
		linelen = strlen(line);
		if (linelen == 0 || line[linelen - 1] != '\n') {
			syslog(LOG_CRIT, "remote delivery failed: corrupted queue file");
			snprintf(errmsg, sizeof(errmsg), "corrupted queue file");
			error = -1;
			goto out;
		}

		/* Remove trailing \n's and escape leading dots */
		trim_line(line);

		/*
		 * If the first character is a dot, we escape it so the line
		 * length increases
		*/
		if (line[0] == '.')
			linelen++;

		if (send_remote_command(fd, "%s", line) != (ssize_t)linelen+1) {
			syslog(LOG_NOTICE, "remote delivery deferred: write error");
			error = 1;
			goto out;
		}
	}

	send_remote_command(fd, ".");
	READ_REMOTE_CHECK("final DATA", 2);

	send_remote_command(fd, "QUIT");
	if (read_remote(fd, 0, NULL) != 2)
		syslog(LOG_INFO, "remote delivery succeeded but QUIT failed: %s", neterr);
out:

	close_connection(fd);
	return (error);
}

static int
sort_pref(const void *a, const void *b)
{
	const struct mx_hostentry *ha = a, *hb = b;
	int v;

	/* sort increasing by preference primarily */
	v = ha->pref - hb->pref;
	if (v != 0)
		return (v);

	/* sort PF_INET6 before PF_INET */
	v = - (ha->ai.ai_family - hb->ai.ai_family);
	return (v);
}

static int
add_host(int pref, const char *host, int port, struct mx_hostentry **he, size_t *ps)
{
	struct addrinfo hints, *res, *res0 = NULL;
	char servname[10];
	struct mx_hostentry *p;
	const int count_inc = 10;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	snprintf(servname, sizeof(servname), "%d", port);
	switch (getaddrinfo(host, servname, &hints, &res0)) {
	case 0:
		break;
	case EAI_AGAIN:
	case EAI_NONAME:
		/*
		 * EAI_NONAME gets returned for:
		 * SMARTHOST set but DNS server not reachable -> defer
		 * SMARTHOST set but DNS server returns "host does not exist"
		 *           -> buggy configuration
		 *           -> either defer or bounce would be ok -> defer
		 * MX entry was returned by DNS server but name doesn't resolve
		 *           -> hopefully transient situation -> defer
		 * all other DNS problems should have been caught earlier
		 * in get_mx_list().
		 */
		goto out;
	default:
		return(-1);
	}

	for (res = res0; res != NULL; res = res->ai_next) {
		if (*ps + 1 >= roundup(*ps, count_inc)) {
			size_t newsz = roundup(*ps + 2, count_inc);
			*he = reallocf(*he, newsz * sizeof(**he));
			if (*he == NULL)
				goto out;
		}

		p = &(*he)[*ps];
		strlcpy(p->host, host, sizeof(p->host));
		p->pref = pref;
		p->ai = *res;
		p->ai.ai_addr = NULL;
		bcopy(res->ai_addr, &p->sa, p->ai.ai_addrlen);

		getnameinfo((struct sockaddr *)&p->sa, p->ai.ai_addrlen,
			    p->addr, sizeof(p->addr),
			    NULL, 0, NI_NUMERICHOST);

		(*ps)++;
	}
	freeaddrinfo(res0);

	return (0);

out:
	if (res0 != NULL)
		freeaddrinfo(res0);
	return (1);
}

static int
get_mx_list(const char *host, int port, struct mx_hostentry **he, int no_mx)
{
	char outname[MAXDNAME];
	ns_msg msg;
	ns_rr rr;
	const char *searchhost;
	const unsigned char *cp;
	unsigned char *ans;
	struct mx_hostentry *hosts = NULL;
	size_t nhosts = 0;
	size_t anssz;
	int pref;
	int cname_recurse;
	int have_mx = 0;
	int err;
	int i;

	res_init();
	searchhost = host;
	cname_recurse = 0;

	anssz = 65536;
	ans = malloc(anssz);
	if (ans == NULL)
		return (1);

	if (no_mx)
		goto out;

repeat:
	err = res_search(searchhost, ns_c_in, ns_t_mx, ans, anssz);
	if (err < 0) {
		switch (h_errno) {
		case NO_DATA:
			/*
			 * Host exists, but no MX (or CNAME) entry.
			 * Not an error, use host name instead.
			 */
			goto out;
		case TRY_AGAIN:
			/* transient error */
			goto transerr;
		case NO_RECOVERY:
		case HOST_NOT_FOUND:
		default:
			errno = ENOENT;
			goto err;
		}
	}

	if (!ns_initparse(ans, anssz, &msg))
		goto transerr;

	switch (ns_msg_getflag(msg, ns_f_rcode)) {
	case ns_r_noerror:
		break;
	case ns_r_nxdomain:
		goto err;
	default:
		goto transerr;
	}

	for (i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
		if (ns_parserr(&msg, ns_s_an, i, &rr))
			goto transerr;

		cp = ns_rr_rdata(rr);

		switch (ns_rr_type(rr)) {
		case ns_t_mx:
			have_mx = 1;
			pref = ns_get16(cp);
			cp += 2;
			err = ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
						 cp, outname, sizeof(outname));
			if (err < 0)
				goto transerr;

			err = add_host(pref, outname, port, &hosts, &nhosts);
			if (err == -1)
				goto err;
			break;

		case ns_t_cname:
			err = ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
						 cp, outname, sizeof(outname));
			if (err < 0)
				goto transerr;

			/* Prevent a CNAME loop */
			if (cname_recurse++ > 10)
				goto err;

			searchhost = outname;
			goto repeat;

		default:
			break;
		}
	}

out:
	err = 0;
	if (0) {
transerr:
		if (nhosts == 0)
			err = 1;
	}
	if (0) {
err:
		err = -1;
	}

	free(ans);

	if (err == 0) {
		if (!have_mx) {
			/*
			 * If we didn't find any MX, use the hostname instead.
			 */
			err = add_host(0, host, port, &hosts, &nhosts);
		} else if (nhosts == 0) {
			/*
			 * We did get MX, but couldn't resolve any of them
			 * due to transient errors.
			 */
			err = 1;
		}
	}

	if (nhosts > 0) {
		qsort(hosts, nhosts, sizeof(*hosts), sort_pref);
		/* terminate list */
		*hosts[nhosts].host = 0;
	} else {
		if (hosts != NULL)
			free(hosts);
		hosts = NULL;
	}

	*he = hosts;
	return (err);

	free(ans);
	if (hosts != NULL)
		free(hosts);
	return (err);
}

static int
init_cert_file(SSL_CTX *ctx, const char *path)
{
	int error;

	/* Load certificate into ctx */
	error = SSL_CTX_use_certificate_chain_file(ctx, path);
	if (error < 1) {
		syslog(LOG_ERR, "SSL: Cannot load certificate `%s': %s", path, ssl_errstr());
		return (-1);
	}

	/* Add private key to ctx */
	error = SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM);
	if (error < 1) {
		syslog(LOG_ERR, "SSL: Cannot load private key `%s': %s", path, ssl_errstr());
		return (-1);
	}

	/*
	 * Check the consistency of a private key with the corresponding
         * certificate
	 */
	error = SSL_CTX_check_private_key(ctx);
	if (error < 1) {
		syslog(LOG_ERR, "SSL: Cannot check private key: %s", ssl_errstr());
		return (-1);
	}

	return (0);
}

int
smtp_init_crypto(int fd, int feature)
{
	SSL_CTX *ctx = NULL;
#if (OPENSSL_VERSION_NUMBER >= 0x00909000L)
	const SSL_METHOD *meth = NULL;
#else
	SSL_METHOD *meth = NULL;
#endif
	X509 *cert;
	int error;

	/* XXX clean up on error/close */
	/* Init SSL library */
	SSL_library_init();
	SSL_load_error_strings();

	meth = TLSv1_client_method();

	ctx = SSL_CTX_new(meth);
	if (ctx == NULL) {
		syslog(LOG_WARNING, "remote delivery deferred: SSL init failed: %s", ssl_errstr());
		return (1);
	}

	/* User supplied a certificate */
	if (config.certfile != NULL) {
		error = init_cert_file(ctx, config.certfile);
		if (error) {
			syslog(LOG_WARNING, "remote delivery deferred");
			return (1);
		}
	}

	/*
	 * If the user wants STARTTLS, we have to send EHLO here
	 */
	if (((feature & SECURETRANS) != 0) &&
	     (feature & STARTTLS) != 0) {
		/* TLS init phase, disable SSL_write */
		config.features |= NOSSL;

		send_remote_command(fd, "EHLO %s", mailname());
		if (read_remote(fd, 0, NULL) == 2) {
			send_remote_command(fd, "STARTTLS");
			if (read_remote(fd, 0, NULL) != 2) {
				if ((feature & TLS_OPP) == 0) {
					syslog(LOG_ERR, "remote delivery deferred: STARTTLS not available: %s", neterr);
					return (1);
				} else {
					syslog(LOG_INFO, "in opportunistic TLS mode, STARTTLS not available: %s", neterr);
					return (0);
				}
			}
		}
		/* End of TLS init phase, enable SSL_write/read */
		config.features &= ~NOSSL;
	}

	config.ssl = SSL_new(ctx);
	if (config.ssl == NULL) {
		syslog(LOG_NOTICE, "remote delivery deferred: SSL struct creation failed: %s",
		       ssl_errstr());
		return (1);
	}

	/* Set ssl to work in client mode */
	SSL_set_connect_state(config.ssl);

	/* Set fd for SSL in/output */
	error = SSL_set_fd(config.ssl, fd);
	if (error == 0) {
		syslog(LOG_NOTICE, "remote delivery deferred: SSL set fd failed: %s",
		       ssl_errstr());
		return (1);
	}

	/* Open SSL connection */
	error = SSL_connect(config.ssl);
	if (error < 0) {
		syslog(LOG_ERR, "remote delivery deferred: SSL handshake failed fatally: %s",
		       ssl_errstr());
		return (1);
	}

	/* Get peer certificate */
	cert = SSL_get_peer_certificate(config.ssl);
	if (cert == NULL) {
		syslog(LOG_WARNING, "remote delivery deferred: Peer did not provide certificate: %s",
		       ssl_errstr());
	}
	X509_free(cert);

	return (0);
}

/*
 * hmac_md5() taken out of RFC 2104.  This RFC was written by H. Krawczyk,
 * M. Bellare and R. Canetti.
 *
 * text      pointer to data stream
 * text_len  length of data stream
 * key       pointer to authentication key
 * key_len   length of authentication key
 * digest    caller digest to be filled int
 */
void
hmac_md5(unsigned char *text, int text_len, unsigned char *key, int key_len,
    unsigned char* digest)
{
        MD5_CTX context;
        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
        unsigned char tk[16];
        int i;
        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {

                MD5_CTX      tctx;

                MD5_Init(&tctx);
                MD5_Update(&tctx, key, key_len);
                MD5_Final(tk, &tctx);

                key = tk;
                key_len = 16;
        }

        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
	 *
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        bzero( k_ipad, sizeof k_ipad);
        bzero( k_opad, sizeof k_opad);
        bcopy( key, k_ipad, key_len);
        bcopy( key, k_opad, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner MD5
         */
        MD5_Init(&context);                   /* init context for 1st
                                              * pass */
        MD5_Update(&context, k_ipad, 64);     /* start with inner pad */
        MD5_Update(&context, text, text_len); /* then text of datagram */
        MD5_Final(digest, &context);          /* finish up 1st pass */
        /*
         * perform outer MD5
         */
        MD5_Init(&context);                   /* init context for 2nd
                                              * pass */
        MD5_Update(&context, k_opad, 64);     /* start with outer pad */
        MD5_Update(&context, digest, 16);     /* then results of 1st
                                              * hash */
        MD5_Final(digest, &context);          /* finish up 2nd pass */
}

/*
 * CRAM-MD5 authentication
 */
int
smtp_auth_md5(int fd, char *login, char *password)
{
	unsigned char digest[BUF_SIZE];
	char buffer[BUF_SIZE], ascii_digest[33];
	char *temp;
	int len, i;
	static char hextab[] = "0123456789abcdef";

	temp = calloc(BUF_SIZE, 1);
	memset(buffer, 0, sizeof(buffer));
	memset(digest, 0, sizeof(digest));
	memset(ascii_digest, 0, sizeof(ascii_digest));

	/* Send AUTH command according to RFC 2554 */
	send_remote_command(fd, "AUTH CRAM-MD5");
	if (read_remote(fd, sizeof(buffer), buffer) != 3) {
		syslog(LOG_DEBUG, "smarthost authentication:"
		       " AUTH cram-md5 not available: %s", neterr);
		/* if cram-md5 is not available */
		free(temp);
		return (-1);
	}

	/* skip 3 char status + 1 char space */
	base64_decode(buffer + 4, temp);
	hmac_md5((unsigned char *)temp, strlen(temp),
		 (unsigned char *)password, strlen(password), digest);
	free(temp);

	ascii_digest[32] = 0;
	for (i = 0; i < 16; i++) {
		ascii_digest[2*i] = hextab[digest[i] >> 4];
		ascii_digest[2*i+1] = hextab[digest[i] & 15];
	}

	/* prepare answer */
	snprintf(buffer, BUF_SIZE, "%s %s", login, ascii_digest);

	/* encode answer */
	len = base64_encode(buffer, strlen(buffer), &temp);
	if (len < 0) {
		syslog(LOG_ERR, "can not encode auth reply: %m");
		return (-1);
	}

	/* send answer */
	send_remote_command(fd, "%s", temp);
	free(temp);
	if (read_remote(fd, 0, NULL) != 2) {
		syslog(LOG_WARNING, "remote delivery deferred:"
				" AUTH cram-md5 failed: %s", neterr);
		return (-2);
	}

	return (0);
}

/*[TODO;
[x] switch from 'hostname' to 'mailname'
[x] merge 'dns.c'
[x] strip testing block after merge
[x] merge 'crypto.c'
]*/
