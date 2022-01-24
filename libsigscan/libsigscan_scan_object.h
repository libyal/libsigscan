/*
 * Scan object functions
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

#if !defined( _LIBSIGSCAN_SCAN_OBJECT_H )
#define _LIBSIGSCAN_SCAN_OBJECT_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_scan_object libsigscan_scan_object_t;

struct libsigscan_scan_object
{
	/* The type
	 */
	uint8_t type;

	/* The value
	 * Contains a scan tree node or a signature
	 */
	intptr_t *value;
};

int libsigscan_scan_object_initialize(
     libsigscan_scan_object_t **scan_object,
     uint8_t type,
     intptr_t *value,
     libcerror_error_t **error );

int libsigscan_scan_object_free(
     libsigscan_scan_object_t **scan_object,
     libcerror_error_t **error );

int libsigscan_scan_object_get_type(
     libsigscan_scan_object_t *scan_object,
     uint8_t *type,
     libcerror_error_t **error );

int libsigscan_scan_object_get_value(
     libsigscan_scan_object_t *scan_object,
     intptr_t **value,
     libcerror_error_t **error );

#if defined( HAVE_DEBUG_OUTPUT )

int libsigscan_scan_object_printf(
     libsigscan_scan_object_t *scan_object,
     libcerror_error_t **error );

#endif /* defined( HAVE_DEBUG_OUTPUT ) */

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_SCAN_OBJECT_H ) */

