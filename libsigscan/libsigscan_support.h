/*
 * Support functions
 *
 * Copyright (C) 2014-2022, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#if !defined( _LIBSIGSCAN_SUPPORT_H )
#define _LIBSIGSCAN_SUPPORT_H

#include <common.h>
#include <types.h>

#include "libsigscan_extern.h"
#include "libsigscan_libbfio.h"
#include "libsigscan_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

#if !defined( HAVE_LOCAL_LIBSIGSCAN )

LIBSIGSCAN_EXTERN \
const char *libsigscan_get_version(
             void );

LIBSIGSCAN_EXTERN \
int libsigscan_get_access_flags_read(
     void );

LIBSIGSCAN_EXTERN \
int libsigscan_get_codepage(
     int *codepage,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_set_codepage(
     int codepage,
     libcerror_error_t **error );

#endif /* !defined( HAVE_LOCAL_LIBSIGSCAN ) */

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_SUPPORT_H ) */

