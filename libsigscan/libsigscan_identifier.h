/*
 * Identifier functions
 *
 * Copyright (C) 2014-2024, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _LIBSIGSCAN_IDENTIFIER_H )
#define _LIBSIGSCAN_IDENTIFIER_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_identifier libsigscan_identifier_t;

struct libsigscan_identifier
{
	/* The string
	 */
	char *string;

	/* The string size
	 */
	size_t string_size;
};

int libsigscan_identifier_initialize(
     libsigscan_identifier_t **identifier,
     libcerror_error_t **error );

int libsigscan_identifier_free(
     libsigscan_identifier_t **identifier,
     libcerror_error_t **error );

int libsigscan_identifier_get_string_size(
     libsigscan_identifier_t *identifier,
     size_t *string_size,
     libcerror_error_t **error );

int libsigscan_identifier_get_string(
     libsigscan_identifier_t *identifier,
     char *string,
     size_t string_size,
     libcerror_error_t **error );

int libsigscan_identifier_set(
     libsigscan_identifier_t *identifier,
     const char *string,
     size_t string_length,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_IDENTIFIER_H ) */

