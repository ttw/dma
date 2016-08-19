%{
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "conf_yy.tab.h"
%}

%option prefix="conf_yy"
%option case-insensitive
%option noyywrap

%state TOKEN VALUE

%%

#.*	/* ignore comments */

<INITIAL>[ \t]*	/* ignore whitespace */

<INITIAL>[\n]*	/* ignore newlines */

<INITIAL>^PORT	{ BEGIN TOKEN ; return( PORT ) ; }
<INITIAL>^ALIASES	{ BEGIN TOKEN ; return(ALIASES) ; }
<INITIAL>^AUTHPATH	{ BEGIN TOKEN ; return(AUTHPATH) ; }
<INITIAL>^MAILNAME	{ BEGIN TOKEN ; return(MAILNAME) ; }
<INITIAL>^MASQUERADE	{ BEGIN TOKEN ; return(MASQUERADE) ; }
<INITIAL>^SECURETRANSFER	{ BEGIN TOKEN ; return(SECURETRANSFER) ; }
<INITIAL>^SMARTHOST	{ BEGIN TOKEN ; return(SMARTHOST) ; }
<INITIAL>^SPOOLDIR	{ BEGIN TOKEN ; return(SPOOLDIR) ; }
<INITIAL>^CERTFILE	{ BEGIN TOKEN ; return(CERTFILE) ; }
<INITIAL>^DEFER	{ BEGIN TOKEN ; return(DEFER) ; }
<INITIAL>^FULLBOUNCE	{ BEGIN TOKEN ; return(FULLBOUNCE) ; }
<INITIAL>^NULLCLIENT	{ BEGIN TOKEN ; return(NULLCLIENT) ; }
<INITIAL>^OPPORTUNISTIC_TLS	{ BEGIN TOKEN ; return(OPPORTUNISTIC_TLS) ; }
<INITIAL>^SECURE	{ BEGIN TOKEN ; return(SECURE) ; }
<INITIAL>^STARTTLS	{ BEGIN TOKEN ; return(STARTTLS) ; }

<TOKEN>[ \t]*	BEGIN VALUE ;

<TOKEN>[\n]*	BEGIN INITIAL ;

<VALUE>[0-9]*	{	/* NUM */
		BEGIN INITIAL ;
		conf_yylval.tok = strdup(conf_yytext) ;
		return( NUM ) ;
	}

<VALUE>[^#\n]*	{	/* STR */
		BEGIN INITIAL ;
		conf_yylval = strdup(conf_yytext) ;
		return( STR ) ;
	}

%%
