/*
 * Error functions
 *
 * Copyright (C) 2014-2017, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined( _LIBSIGSCAN_INTERNAL_ERROR_H )
#define _LIBSIGSCAN_INTERNAL_ERROR_H

#include <common.h>
#include <file_stream.h>
#include <types.h>

#if !defined( HAVE_LOCAL_LIBSIGSCAN )
#include <libsigscan/error.h>
#endif

#include "libsigscan_extern.h"

#if defined( __cplusplus )
extern "C" {
#endif

#if !defined( HAVE_LOCAL_LIBSIGSCAN )

LIBSIGSCAN_EXTERN \
void libsigscan_error_free(
      libsigscan_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_error_fprint(
     libsigscan_error_t *error,
     FILE *stream );

LIBSIGSCAN_EXTERN \
int libsigscan_error_sprint(
     libsigscan_error_t *error,
     char *string,
     size_t size );

LIBSIGSCAN_EXTERN \
int libsigscan_error_backtrace_fprint(
     libsigscan_error_t *error,
     FILE *stream );

LIBSIGSCAN_EXTERN \
int libsigscan_error_backtrace_sprint(
     libsigscan_error_t *error,
     char *string,
     size_t size );

#endif /* !defined( HAVE_LOCAL_LIBSIGSCAN ) */

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_INTERNAL_ERROR_H ) */

