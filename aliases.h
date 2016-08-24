#ifndef ALIASES_DMA_H
#define ALIASES_DMA_H 

#include <sys/queue.h>
#include <sysexits.h>

struct aliases_list*
aliases_parse( struct aliases_list*, const char* ) ;

int
aliases_err( int ) ;

struct alias*
alias_new( struct alias* ) ;

struct aliases_entry*
aliases_entry_new( struct aliases_entry* ) ;

struct alias_list*
alias_list_new( struct alias_list* ) ;

struct aliases_list*
aliases_list_new( struct aliases_list* ) ;

enum aliases_err {
	ALIASES_ERR_NONE = EX_OK,
	ALIASES_ERR_BASE = EX__BASE,
	ALIASES_ERR_SOFTWARE = EX_SOFTWARE,
	ALIASES_ERR_UNREACHABLE = EX_UNAVAILABLE,
	ALIASES_ERR_CUSTOM = 127,
	ALIASES_ERR_MAX
} ;
#define ALIASES_SUCCESS ALIASES_ERR_NONE
#define ALIASES_GET_ERR ALIASES_ERR_NONE

enum {	/* really ALIAS_TYPE but ... huh? */
	ALIAS_NULL,
	ALIAS_ADDR,	/* default */
	ALIAS_CMD,	/* [ ] */
	ALIAS_FILE,	/* [ ] must exist; if directory then use maildir format otherwise use mbox format */
	ALIAS_URL,	/* [ ] e.g. POST to HTTP server */
	ALIAS_MAX
} ;

struct alias {
	SLIST_ENTRY(alias) list ;
	int type ;
	char *entry ;
} ;
SLIST_HEAD( alias_list, alias ) ;

struct aliases_entry {
	SLIST_ENTRY(aliases_entry) list ;
	char *name ;
	struct alias_list *aliases ;	/* need pointer because we create the alias_list first */
};
SLIST_HEAD( aliases_list, aliases_entry ) ;

#endif /* ALIASES_DMA_H */
