/*
 * Signature functions
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

#if !defined( _LIBSIGSCAN_SIGNATURE_H )
#define _LIBSIGSCAN_SIGNATURE_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_signature libsigscan_signature_t;

struct libsigscan_signature
{
	/* The identifier
	 */
	char *identifier;

	/* The identifier size
	 */
	size_t identifier_size;

	/* The pattern offset
	 */
	off64_t pattern_offset;

	/* The pattern
	 */
	uint8_t *pattern;

	/* The pattern size
	 */
	size_t pattern_size;

	/* The signature flags
	 */
	uint32_t signature_flags;
};

int libsigscan_signature_initialize(
     libsigscan_signature_t **signature,
     libcerror_error_t **error );

int libsigscan_signature_free(
     libsigscan_signature_t **signature,
     libcerror_error_t **error );

int libsigscan_signature_free_clone(
     libsigscan_signature_t **signature,
     libcerror_error_t **error );

int libsigscan_signature_clone(
     libsigscan_signature_t **destination_signature,
     libsigscan_signature_t *source_signature,
     libcerror_error_t **error );

int libsigscan_signature_get_identifier_size(
     libsigscan_signature_t *signature,
     size_t *identifier_size,
     libcerror_error_t **error );

int libsigscan_signature_get_identifier(
     libsigscan_signature_t *signature,
     char *identifier,
     size_t identifier_size,
     libcerror_error_t **error );

int libsigscan_signature_set(
     libsigscan_signature_t *signature,
     const char *identifier,
     size_t identifier_length,
     off64_t pattern_offset,
     const uint8_t *pattern,
     size_t pattern_size,
     uint32_t signature_flags,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_SIGNATURE_H ) */

