#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <sys/queue.h>
#include <sysexits.h>

#include "aliases.h"

static int _aliases_err = 0 ;

#define ALIASES_ERR(x) do { aliases_err(x) ; return(NULL) ; } while(0)

int
aliases_err( int e )
{
	if( e )
	{
		if(_aliases_err) errx(ALIASES_ERR_SOFTWARE,"functional/collosion") ;
		_aliases_err = e ;
		return( e ) ;
	}
	else
	{
		e = _aliases_err ;
		_aliases_err = ALIASES_ERR_NONE ;
		return( e ) ;
	} ;
	errx( ALIASES_ERR_UNREACHABLE, "unreachable" ) ;
} ;

struct alias*
alias_new( struct alias *alias )
{
	static struct alias
	alias_new =
		{
			.type = ALIAS_NULL,
			.entry = NULL,
			} ;
	if( alias == NULL )
	{
		alias = malloc(sizeof(alias_new)) ;
		if(alias == NULL) ALIASES_ERR(ENOMEM) ;
	} ;
	*alias = alias_new ;
	return( alias ) ;
} ;

struct aliases_entry*
aliases_entry_new( struct aliases_entry *aliases_entry )
{
	static struct aliases_entry
	aliases_entry_new =
		{
			.name = NULL,
			.aliases = NULL,
			} ;
	if( aliases_entry == NULL )
	{
		aliases_entry = malloc(sizeof(aliases_entry_new)) ;
		if(aliases_entry == NULL) ALIASES_ERR(ENOMEM) ;
	} ;
	*aliases_entry = aliases_entry_new ;
	return( aliases_entry ) ;
} ;

struct alias_list*
alias_list_new( struct alias_list *alias_list )
{
	if( alias_list == NULL )
	{
		alias_list = malloc(sizeof(struct alias_list)) ;
		if(alias_list == NULL) ALIASES_ERR(ENOMEM) ;
	} ;
	SLIST_INIT( alias_list ) ;
	return( alias_list ) ;
} ;

struct aliases_list*
aliases_list_new( struct aliases_list *aliases_list )
{
	if( aliases_list == NULL )
	{
		aliases_list = malloc(sizeof(struct aliases_list)) ;
		if(aliases_list == NULL) ALIASES_ERR(ENOMEM) ;
	} ;
	SLIST_INIT( aliases_list ) ;
	return( aliases_list ) ;
} ;
