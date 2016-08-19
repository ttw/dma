%{
#include <stdlib.h>

#include "conf.h"

extern FILE *conf_yyin ;

int conf_yylex() ;
%}

%union {
	char *tok ;	/* this is a lexical problem, not a gramatic one */
}

%token NUM
%token STR

%%

config:
	/* empty */
|	config option
;

option:
	option_num
|	option_str
|	option_bool
;

option_num:
	"PORT" NUM	{ config.port = (int)$2 ; }
;

option_str:
	"ALIASES_FILE" STR	{ config.aliases = $2 ) ; }
|	"AUTH_FILE" STR	{ config.authpath = $2 ) ; }
|	"CERTFILE" STR	{ config.certfile = $2 ) ; }
|	"MAILNAME" STR	{ config.mailname = $2 ) ; }
|	"MASQUERADE" STR	{ config.masquerade = $2 ) ; }
|	"SMARTHOST" STR	{ config.smarthost = $2 ) ; }
|	"SPOOLDIR" STR	{ config.spooldir = $2 ) ; }
;

option_bool:
	"DEFER"	{ config.features |= DEFER ; }
|	"FULLBOUNCE"	{ config.features |= FULLBOUNCE ; }
|	"NULLCLIENT"	{ config.features |= NULLCLIENT ; }
|	"OPPORTUNISTIC_TLS"	{ config.features |= TLS_OPP ; }
|	"SECURE"	{ config.features |= SECURE ; }
|	"INSECURE"	{ config.features |= INSECURE ; }
|	"SECURETRANSFER"	{ config.features |= SECURETRANS ; }
|	"STARTTLS"	{ config.features |= STARTTLS ; }
;

%%

struct config*
config_new( struct config *config )
{
	static struct config
	config_new = {
		.aliases_file = DMA_ALIASES_PATH,
		.auth_file = NULL,
		.cert_file = NULL,
		.features = 0,
		.mailname = NULL,
		.masquerade = NULL,
		.port = 25,
		.smarthost = NULL,
		.spool_dir = DMA_SPOOL_DIR,
	};

	if( config == NULL ) {/*XXX: allocate memory*/} ;

	/*XXX: copy config */
	return( config ) ;
} ;

struct config*
config_parse( struct config *config, char *config_file )
{

	if(config == NULL) return(NULL) ;
	if(conf_yyparse_config != NULL) return(NULL) ;
	if(conf_yyin) return(NULL) ;

	conf_yyin = fopen( config_file, "r" ) ;
	if(!conf_yyin) return(NULL) ;
	conf_yyparse_config = config ;
	conf_yyparse() ;
} ;

static void
conf_yyerror( char const *str )
{
	fprintf( stderr, "%s\n", str ) ;
	fclose( conf_yyin ) ;
} ;
