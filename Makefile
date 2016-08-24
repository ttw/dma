# See README.install

help:
	$(PAGER) README.install

DMA_VERSION_MAJOR=0
DMA_VERSION_MINOR=11

DMA_VERSION=v$(DMA_VERSION_MAJOR).$(DMA_VERSION_MINOR)
DMA_VERSION_DEFINE=-DDMA_VERSION='"$(DMA_VERSION)"'

PREFIX?=/usr/local

ETC_DIR?=$(PREFIX)/etc
LIBEXEC_DIR?=$(PREFIX)/libexec
SBIN_DIR?=$(PREFIX)/sbin
SHARE_DIR?=$(PREFIX)/share
VAR_DIR?=$(PREFIX)/var

MAIL_DIR?=$(VAR_DIR)/mail
MAN_DIR?=$(SHARE_DIR)/man
SPOOL_DIR?=$(VAR_DIR)/spool

DMA_CONF_DIR=$(ETC_DIR)/dma
DMA_SPOOL_DIR=$(SPOOL_DIR)/dma
DMA_SPOOL_DIR_DEFINE=-DDMA_SPOOL_DIR='"$(DMA_SPOOL_DIR)"'

DMA_ALIASES_PATH=$(ETC_DIR)/aliases
DMA_ALIASES_PATH_DEFINE=-DDMA_ALIASES_PATH='"$(DMA_ALIASES_PATH)"'
DMA_AUTH=auth.conf
DMA_AUTH_PATH=$(DMA_CONF_DIR)/auth.conf
DMA_BIN=dma
DMA_CONF=dma.conf
DMA_CONF_PATH=$(DMA_CONF_DIR)/$(DMA_CONF)
DMA_CONF_PATH_DEFINE=-DDMA_CONF_PATH='"$(DMA_CONF_PATH)"'
DMA_GROUP=mail
DMA_MAN=dma.8
DMA_USER=mail#	see 'dma.c'
DMA_USER_DEFINE+=-DDMA_USER='"$(DMA_USER)"'

DMA_FEATURE_MBOX_STRICT?=0#	strict mbox processing only requires escaping after empty lines, yet most MUAs seem to relax this requirement and will treat any line starting with "From " as the beginning of a new mail.
DMA_FEATURE_MBOX_STRICT_DEFINE=-DMBOX_STRICT='$(DMA_FEATURE_MBOX_STRICT)'

DMA_SRC+=base64.c
DMA_SRC+=config.c
DMA_SRC+=dma.c
DMA_SRC+=local.c
DMA_SRC+=mail.c
DMA_SRC+=net.c
DMA_SRC+=spool.c
DMA_SRC+=util.c
DMA_SRC_LEX+=aliases.l
DMA_SRC_LEX+=config.l
DMA_SRC_YACC+=aliases.y
DMA_SRC_YACC+=config.y

DMA_OBJ+=aliases.o
DMA_OBJ+=aliases_yy.lex.o
DMA_OBJ+=aliases_yy.tab.o
DMA_OBJ+=base64.o
DMA_OBJ+=config.o
DMA_OBJ+=config_yy.lex.o
DMA_OBJ+=config_yy.tab.o
DMA_OBJ+=dma.o
DMA_OBJ+=local.o
DMA_OBJ+=mail.o
DMA_OBJ+=net.o
DMA_OBJ+=spool.o
DMA_OBJ+=util.o

DMA_LIB+=-lssl
DMA_LIB+=-lcrypto
#DMA_LIB+=-lresolv

DMA_MBOXCREATE_BIN=dma-mbox-create
DMA_MBOXCREATE_BIN_DEFINE=-DMBOXCREATE_BIN='"$(DMA_MBOXCREATE_BIN)"'
DMA_MBOXCREATE_PATH_DEFINE=-DMBOXCREATE_PATH='"$(LIBEXEC_DIR)/$(DMA_MBOXCREATE_BIN)"'

DMAMBOXCREATE_GROUP_DEFINE+=-DDMA_GROUP='"$(DMA_GROUP)"'

DMAMBOXCREATE_SRC+=dma-mbox-create.c

DMAMBOXCREATE_OBJ+=dma-mbox-create.o

OS_SRC+=os/getprogname.c
OS_SRC+=os/reallocf.c
OS_SRC+=os/setprogname.c
OS_SRC+=os/strlcpy.c

OS_OBJ+=os/getprogname.o
OS_OBJ+=os/reallocf.o
OS_OBJ+=os/setprogname.o
OS_OBJ+=os/strlcpy.o

# PROGRAM DEFINITIONS

CC?=cc
CHGRP?=chgrp
CHMOD?=chmod
INSTALL?=install
LEX?=lex
LN?=ln
PAGER?=less
RM?=rm
YACC?=yacc

INSTALL_OWN=root
INSTALL_GRP=mail
INSTALL_MODE_SUID=4555
INSTALL_MODE_GSUID=2555
INSTALL_SHARE_OWN=root
INSTALL_SHARE_GRP=wheel
INSTALL_SHARE_MODE=755

# COMPILATION AND LINKING DEFINITIONS

CFLAGS?=-O -pipe -Wall

.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

#.l.c:
#	$(LEX) -t -o $@ $(.IMPSRC:S/_yy.lex.c/.l/)
#lex -o config_yy.lex.c config.l
#lex -o aliases_yy.lex.c aliases.l

#.y.c:
#	$(YACC) -d -o $@ $(.IMPSRC:S/_yy.lex.c/.l)
#yacc -d -b config_yy -p config_yy config.y
#yacc -d -b aliases_yy -p aliases_yy aliases.y

aliases_yy.lex.o: aliases.l
	$(LEX) -o aliases_yy.lex.c aliases.l \
	&& $(CC) -o $@ aliases_yy.lex.c \
	&& $(RM) aliases_yy.lex.c

aliases_yy.tab.o: aliases.y
	$(YACC) -d -b aliases_yy -p aliases_yy aliases.y \
	&& $(CC) -c -o $@ aliases_yy.tab.c \
	&& $(RM) aliases_yy.tab.[ch]

config_yy.lex.o: config.l
	$(LEX) -o config_yy.lex.c config.l \
	&& $(CC) -o $@ config_yy.lex.c \
	&& $(RM) config_yy.lex.c

config_yy.tab.o: config.y
	$(YACC) -d -b config_yy -p config_yy config.y \
	&& $(CC) -c -o $@ config_yy.tab.c \
	&& $(RM) config_yy.tab.[ch]

local.o: local.c
	$(CC) $(CFLAGS) \
			$(DMA_FEATURE_MBOX_STRICT_DEFINE) \
			$(DMA_MBOXCREATE_BIN_DEFINE) \
			$(DMA_MBOXCREATE_PATH_DEFINE) \
			-c -o $@ $>

dma.o: dma.c
	$(CC) $(CFLAGS) \
			$(DMA_ALIASES_PATH_DEFINE) \
			$(DMA_CONF_PATH_DEFINE) \
			$(DMA_SPOOL_DIR_DEFINE) \
			$(DMA_USER_DEFINE) \
			-c -o $@ $>

mail.o: mail.c
	$(CC) $(CFLAGS) \
			$(DMA_VERSION_DEFINE) \
			-c -o $@ $<

dma: $(DMA_OBJ)
	$(CC) $(LDFLAGS) $(DMA_LIB) -o $@ $>

dma-mbox-create: $(DMAMBOXCREATE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $<

dma-mbox-create.o: dma-mbox-create.c
	$(CC) $(CFLAGS) $(DMAMBOXCREATE_GROUP_DEFINE)

build-all: dma-build dmamboxcreate-build

dma-build:
	$(MAKE) $(MAKEFILE) build

dmamboxcreate-build:
	$(MAKE) -f mk/dmamboxcreate.mk build

features:
	@sed -e '/^DMA_FEATURE_/ ! d' $(MAKEFILE) $(MAKEFILE_LIST)

#clean:
#	rm $(OBJ) 
#
#build:
#
#install:
#
#dma:
#	$(CC) $(CFLAGS) $(CFLAGS_DEFINE_DMA)

# NOTES
#	* Not sure whether I want to have a bare `make` do a 'build' or 'help'.  Will leave it 'help' for now.
#	- This could as easily (or probably more easily) be a shell script but we'll keep with the tradition of a straight `make clean`, `make install` doing what you'd expect.
#	~ Ideally makefile will be able to determine the operating system and the appropriate `make` type and then call the appropriate `make` with the necessary operating system parameters.

#![TODO#build;
#[ ][2016-08-21] lex/yacc stuff is horrific; rethink
#[ ][2016-08-03] SPOOLDIR_FLUSHFILE needs to match the defines
#[ ][2016-08-03] determine make and HAVE parameters for any one OS
#[x][2016-08-03] distill top level definitions
#[x][2016-08-09] add defines as seperate and keep definition with option
#]
