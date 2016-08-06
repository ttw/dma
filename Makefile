# See README.install

DMA_VERSION_MAJOR=0
DMA_VERSION_MINOR=11
DMA_VERSION=v$(DMA_VERSION_MAJOR).$(DMA_VERSION_MINOR)

PREFIX?=/usr/local

ETC_DIR?=$(PREFIX)/etc
LIBEXEC_DIR?=$(PREFIX)/libexec
SBIN_DIR?=$(PREFIX)/sbin
SHARE_DIR?=$(PREFIX)/share
VAR_DIR?=$(PREFIX)/var

MAIL_DIR?=$(VAR_DIR)/mail
MAN_DIR?=$(SHARE_DIR)/man
SPOOL_DIR?=$(VAR_DIR)/spool

DMA_BIN=dma
DMA_BIN_MBOX_CREATE=dma-mbox-create
DMA_CONF_DIR=$(ETC_DIR)/dma
DMA_CONF_FILE=dma.conf
DMA_GROUP=mail
DMA_MAN=dma.8
DMA_SPOOL_DIR=$(SPOOL_DIR)/dma
DMA_USER=mail	# We never run as root.  If called by root, drop permissions to the mail user.

DMA_FEATURE_MBOX_STRICT?=0 # strict mbox processing only requires escaping after empty lines, yet most MUAs seem to relax this requirement and will treat any line starting with "From " as the beginning of a new mail.

SRCS+=aliases_parse.y
SRCS+=aliases_scan.l
SRCS+=base64.c
SRCS+=conf.c
SRCS+=crypto.c
SRCS+=dma-mbox-create.c
SRCS+=dma.c
SRCS+=dns.c
SRCS+=local.c
SRCS+=mail.c
SRCS+=net.c
SRCS+=spool.c
SRCS+=util.c

OBJS+=aliases_parse.o
OBJS+=aliases_scan.o
OBJS+=base64.o
OBJS+=conf.o
OBJS+=crypto.o
OBJS+=dfcompat.o
OBJS+=dma.o
OBJS+=dns.o
OBJS+=local.o
OBJS+=mail.o
OBJS+=net.o
OBJS+=spool.o
OBJS+=util.o

# PROGRAM DEFINITIONS

CC?=cc
CHGRP?=chgrp
CHMOD?=chmod
INSTALL?=install
LEX?=lex
LN?=ln
PAGER?=less
YACC?=yacc

INSTALL_OWN=root
INSTALL_GRP=mail
INSTALL_MODE=2555
INSTALL_SHARE_OWN=root
INSTALL_SHARE_GRP=wheel
INSTALL_SHARE_MODE=755

# COMPILATION AND LINKING DEFINITIONS

CFLAGS_DEFINE_FEATURE+=-DHAVE_REALLOCF
CFLAGS_DEFINE_FEATURE+=-DHAVE_STRLCPY
CFLAGS_DEFINE_FEATURE+=-DHAVE_GETPROGNAME
CFLAGS_DEFINE_FEATURE+=-DHAVE_SYSCONF

CFLAGS_DEFINE_DMA+=-DDMA_VERSION='"$(DMA_VERSION)"'
CFLAGS_DEFINE_DMA+=-DDMA_EXEC_MBOX_CREATE_PATH='"$(LIBEXEC_DIR)/$(DMA_BIN_MBOX_CREATE)"'
CFLAGS_DEFINE_DMA+=-DDMA_CONF_PATH='"$(SYSCONF_DIR)/$(DMA_CONF_FILE)"'

CFLAGS?=-O -pipe -Wall

LDFLAGS+=-lssl
#LDFLAGS+=-lcrypto
#LDFLAGS+=-lresolv

help:
	$(PAGER) README.install

features:
	@sed -e '/^DMA_FEATURE_/ ! d' $(MAKEFILE) $(MAKEFILE_LIST)

clean:
	rm $(OBJ) 

build:

install:

dma:
	cc $(CFLAGS) $(CFLAGS_DEFINE_DMA)

# NOTES
#	* Not sure whether I want to have a bare `make` do a 'build' or 'help'.  Will leave it 'help' for now.
#	- This could as easily (or probably more easily) be a shell script but we'll keep with the tradition of a straight `make clean`, `make install` doing what you'd expect.
#	~ Ideally makefile will be able to determine the operating system and the appropriate `make` type and then call the appropriate `make` with the necessary operating system parameters.

# TASK#build
#Wed Aug  3 22:14:56 UTC 2016
#		SPOOLDIR_FLUSHFILE needs to match the defines
#Wed Aug  3 17:04:18 UTC 2016
#		determine make and HAVE parameters for any one OS
#Wed Aug  3 17:07:24 UTC 2016
#		distill top level definitions
