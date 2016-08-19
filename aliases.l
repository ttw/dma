%{
#include "aliases_yy.tab.h"
%}

%option nounput
%option noyywrap
%option prefix="aliases_yy"
%option yylineno

%state NAME_TOK ALIAS_TOK

%%

[ \t]*	/* ignore linear whitespace */

#[^\n]*	/* ignore comments */

<INITIAL>\n	/* ignore newlines */

<INITIAL>^\"([^"]|\\.)*\"	{	/* quoted NAME */
		BEGIN NAME_TOK ;
		aliases_yylval.tok =
			strndup(
				aliases_yytext + 1,
				aliases_yyleng - 2 ) ;
		return( NAME ) ;
		}

<INITIAL>^[^\t\n #:]*	{	/* NAME */
		BEGIN NAME_TOK ;
		aliases_yylval.tok = strdup(aliases_yytext) ; \
		return( NAME ) ;
		}

<NAME_TOK>:	{	/* ':' seperator */
		BEGIN ALIAS_TOK ;
		return(yytext[0]) ;
		}
			/* [?] we could ignore this (but it clarifies the grammer) */

<ALIAS_TOK>,	{	/* ',' seperator */
		return(yytext[0]) ;
		}
			/* [?] we could ignore this (but it clarifies the grammer) */

<ALIAS_TOK>\"([^"]|\\.)*\"	{	/* quoted ALIAS */
		aliases_yylval.tok =
			strndup(
				aliases_yytext + 1,
				aliases_yyleng - 2 ) ;
		return( ALIAS ) ;
		}

<ALIAS_TOK>[^ \t\n,]*	{	/* ALIAS */
		aliases_yylval.tok = strdup( aliases_yytext ) ;
		return( ALIAS ) ;
		}

<ALIAS_TOK>\n[ \t]+	/* continuation (NB: ',' still required) */

<ALIAS_TOK>\n	{	/* end of values */
		BEGIN INITIAL ;
		}

%%

/*[TODO;
[x] don't like the asymmetry with 'conf', where comments don't need to include '\n' for comments (which seems more correct); why can't I do it here? ... we can; done.
]*/
