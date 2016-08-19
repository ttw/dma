#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "aliases.h"

int parse_good0( int, char*[] ) ;

typedef int(*test_func)( int, char*[] ) ;

struct test {
	test_func t ;
	char *descr ;
	int expect ;
} ;

struct test test_list[] =
	{
		{
			.t = &parse_good0,
			.descr = "parse good data sample",
			.expect = 0 },
		{ NULL }
		} ;

int
main( int argc, char *argv[] )
{
	struct test *test = test_list ;
	pid_t test_pid ;
	int test_result ;
	while( test->t )
	{
		printf( "test/" ) ;
		test_pid = fork() ;
		if( test_pid )
		{
			if( test_pid == -1 )
				errx( 1, "fork" ) ;
			while( waitpid(test_pid,&test_result,WUNTRACED) == test_pid )
			{
				if(WIFSTOPPED(test_result)) continue ;
				assert(WIFEXITED(test_result)) ;
				assert(WEXITSTATUS(test_result) == test->expect) ;
				break ;
			} ;
			printf( "done(%d): %s\n", test_pid, test->descr ) ;
		}
		else
		{
#define DEBUG_TEST NULL
			if( test->t == DEBUG_TEST )
				while(!test_pid) sleep(1) ;
			_exit( test->t(argc,argv) ) ;
		} ;
		test++ ;
	} ;
	printf( "success\n" ) ;
	return( EXIT_SUCCESS ) ;
} ;

int
parse_good0( int argc, char *(argv[]) )
{
	struct aliases_list *aliases ;
	struct aliases_entry *aliases_entry ;
	struct alias *alias ;
	aliases = aliases_parse(NULL, "aliases,SAMPLE,GOOD") ;
	if( aliases )
	{
		SLIST_FOREACH(aliases_entry, aliases, list )
		{
			printf( "name:%s\n", aliases_entry->name ) ;
			SLIST_FOREACH(alias, aliases_entry->aliases, list )
				printf( "\talias:%s\n", alias->entry ) ;
		} ;
		return( EXIT_SUCCESS ) ;
	} ;
	return( EXIT_FAILURE ) ;
} ;
