%{
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <syslog.h>

#include "aliases.h"

int aliases_yylex() ;	/* lex function from 'aliases.l' */
extern FILE *aliases_yyin ;
extern int aliases_yylineno ;

struct aliases_list aliases_list ;
%}

%union {
	char *tok ;	/* this is a lexical problem, not a grammatic one */
	struct alias_list *alias_list ;
}

%token NAME
%token ALIAS

%%

entries	:
	/* EMPTY */
	| entries entry
	;

entry :
	NAME ':' aliases {
			struct aliases_entry *entry ;
			entry = aliases_entry_new(NULL) ;
			if( entry == NULL )
				errx( 007, "aliases/parse/entry/aliases_entry_new" ) ;
			entry->name = $1.tok ;
			entry->aliases = $3.alias_list ;
			SLIST_INSERT_HEAD( &aliases_list, entry, list ) ;
		}
	;

aliases :
/*[TODO;
[ ] figure out the alias type and set them
]*/
	aliases ',' ALIAS {
			struct alias *alias ;
			alias = alias_new(NULL) ;
			if( !alias )
				errx( 007, "aliases/parse/alias/insert/alias_new" ) ;
			alias->entry = $3.tok ;
			SLIST_INSERT_HEAD($1.alias_list, alias, list) ;
			$$ = $1 ;
		}
	| ALIAS {
			struct alias_list *aliases ;
			aliases = alias_list_new(NULL) ;
			if( aliases == NULL )
				errx( 007, "aliases/parse/alias/alias_list_new" ) ;

			struct alias *alias ;
			alias = alias_new(NULL) ;
			if( alias == NULL )
				errx( 100, "aliases/parse/alias/alias_new" ) ;
			alias->entry = $1.tok ;
			SLIST_INSERT_HEAD( aliases, alias, list ) ;
			$$.alias_list = aliases ;
		}
	;

%%

static void
aliases_yyerror(const char *msg)
{
	/**
	 * Because we do error '\n' below, we need to report the error
	 * one line above of what yylineno points to.
	 */
	syslog(LOG_ERR, "aliases/parse?line=%d;msg=\"%s\"", aliases_yylineno-1, msg);
} ;

struct aliases_list*
aliases_parse( struct aliases_list *aliases_list0, const char *aliases_file )
{
	struct aliases_list *aliases_list_old ;
	aliases_yyin = fopen( aliases_file, "r" ) ;
	aliases_yyparse() ;
	fclose( aliases_yyin ) ;
	aliases_list0 = aliases_list_new(aliases_list0) ;
	*aliases_list0 = aliases_list ;
	aliases_list_old = aliases_list_new(&aliases_list) ;
	if( aliases_list_old != &aliases_list )
		errx( ALIASES_ERR_SOFTWARE, "aliases/parse/aliases_list_new?aliases_list&global" ) ;
	return( aliases_list0 ) ;
} ;
