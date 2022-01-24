/*
 * Scan result functions
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

#if !defined( _LIBSIGSCAN_SCAN_RESULT_H )
#define _LIBSIGSCAN_SCAN_RESULT_H

#include <common.h>
#include <types.h>

#include "libsigscan_extern.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_signature.h"
#include "libsigscan_types.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_internal_scan_result libsigscan_internal_scan_result_t;

struct libsigscan_internal_scan_result
{
	/* The offset
	 */
	off64_t offset;

	/* The signature
	 */
	libsigscan_signature_t *signature;
};

LIBSIGSCAN_EXTERN \
int libsigscan_scan_result_initialize(
     libsigscan_scan_result_t **scan_result,
     off64_t offset,
     libsigscan_signature_t *signature,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scan_result_free(
     libsigscan_scan_result_t **scan_result,
     libcerror_error_t **error );

int libsigscan_internal_scan_result_free(
     libsigscan_internal_scan_result_t **internal_scan_result,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scan_result_get_identifier_size(
     libsigscan_scan_result_t *scan_result,
     size_t *identifier_size,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scan_result_get_identifier(
     libsigscan_scan_result_t *scan_result,
     char *identifier,
     size_t identifier_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_SCAN_RESULT_H ) */

