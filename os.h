#ifndef OS_H
#define OS_H
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

/*[MAN;
.Dd
.Dt os.h A
.Os
.Sh os.h : Operating System specific defintions
]*/

#ifndef PATH_MAX
/*[MAN;
.Ss PATH_MAX

Simple configuration paths; don't need anything clever here (so ignore the XOPEN limits).
]*/
#	ifdef _POSIX_PATH_MAX
#		define PATH_MAX _POSIX_PATH_MAX
#	else
#		define PATH_MAX 255
#	endif
#endif

#ifndef HAVE_GETPROGNAME
/*[MAN;
.Ss getprogname

Get program name.
]*/
const char* getprogname( void ) ;
#endif /* !HAVE_GETPROGNAME */

#ifndef HAVE_REALLOCF
/*[MAN;
.Ss relallocf

'realloc' and free if fail.
]*/
void* reallocf( void*, size_t ) ;
#endif /* !HAVE_REALLOCF */

#ifndef HAVE_SETPROGNAME
/*[MAN;
.Ss setprogname

Set program name.
]*/
void setprogname( const char* ) ;
#endif /* !HAVE_SETPROGNAME */

#ifndef HAVE_STRLCPY
/*[MAN;
.Ss strlcpy

Consistent 'strcpy' function.
]*/
size_t strlcpy( char*, const char*, size_t ) ;
#endif /* !HAVE_STRLCPY */

#ifndef HAVE_SYSCONF
/*[MAN;
.Ss sysconf

Get system configuration.
]*/
enum {
	_SC_HOST_NAME_MAX
} ;
long sysconf( int );
#endif /* !HAVE_SYSCONF */

#endif /* OS_H */

/*[TODO;
[x] move prototypes for optional functions from 'dfcompat.h'
[x] get the POSIX definitions (include cdefs.h)
]*/
