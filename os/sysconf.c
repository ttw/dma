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

#ifndef HAVE_SYSCONF
/*[MAN;
Define a fall back value for
.Pa HOST_NAME_MAX
which is only used if
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

#include "../os.h"

long
sysconf( int name )
{
	switch( name )
	{
	case _SC_HOST_NAME_MAX:
		return( HOST_NAME_MAX ) ;
	} ;
	errno = EINVAL ;
	return( _SC_ERR ) ;
} ;
#endif /* HAVE_SYSCONF */

/*[TODO;
[x] include 'os.h'
[x] 'dma_host_name_max_sysconf' cannot be inline (has static variable)
]*/
