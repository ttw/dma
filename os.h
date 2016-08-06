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

/*[MAN;
.Ss PATH_MAX

Simple configuration paths; don't need anything clever here (so ignore the XOPEN limits).
]*/
#ifndef PATH_MAX
#	ifdef _POSIX_PATH_MAX
#		define PATH_MAX _POSIX_PATH_MAX
#	else
#		define PATH_MAX 255
#	endif
#endif

/*[MAN;
.Ss dma_host_name_max
Define a function for getting the
.Pa HOST_NAME_MAX
using either the definition or
.Pa sysconf .
]*/
#if defined(HAVE_SYSCONF) && __POSIX_VISIBLE >= 200112
#	define dma_host_name_max dma_host_name_max_sysconf
#elif defined(HOST_NAME_MAX)
#	define dma_host_name_max HOST_NAME_MAX
#elif defined(_POSIX_HOST_NAME_MAX)
#	define dma_host_name_max _POSIX_HOST_NAME_MAX
#else
#	error unable to define maximum hostname length.
#endif
/*[MAN;
We also define a fall back value for
.Pa HOST_NAME_MAX
which is only used
.Pa sysconf
fails for some reason.
]*/
#ifndef HOST_NAME_MAX
#	ifdef _POSIX_HOST_NAME_MAX
#		define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#	else
#		define HOST_NAME_MAX 255
#	endif
#endif
