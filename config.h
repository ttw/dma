/*
 * Copyright (c) 2016, n0goOi3 <ttw@cobbled.net>.  All rights reserved.
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

/*
DMA_VERSION
DMA_SPOOL_DIR
DMA_ALIASES_PATH
DMA_CONF_PATH
DMA_USER
DMA_GROUP
MBOX_STRICT
MBOXCREATE_BIN
MBOXCREATE_PATH
*/

struct config {
	const char *aliases_file ;
	const char *auth_file ;
	const char *cert_file ;
	const char *mailname ;
	const char *masquerade ;
	int port ;	/* [ ] merge with smarthost */
	const char *smarthost ;
	const char *spool_dir ;

	int features ;
} ;
#define FEATURE_DEFER       0x0001	/* Defer mails */
#define FEATURE_FULLBOUNCE  0x0002	/* Bounce the full message */
#define FEATURE_INSECURE    0x0004	/* Allow plain login w/o encryption */
#define FEATURE_NOSSL       0x0008	/* Do not use SSL */
#define FEATURE_NULLCLIENT  0x0010	/* Nullclient support */
#define FEATURE_SECURE      0x0020	/* Mutually exclusive to INSECURE but the definitions are all screwy anyway */
#define FEATURE_SECURETRANS 0x0040	/* SSL/TLS in general */
#define FEATURE_STARTTLS    0x0080	/* StartTLS support */
#define FEATURE_TLS_OPP     0x0100	/* Opportunistic STARTTLS */

config_smarthost() ;
config_
const char* mailname() ;
