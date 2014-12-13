/*
 * Skip table functions
 *
 * Copyright (c) 2014, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _LIBSIGSCAN_SKIP_TABLE_H )
#define _LIBSIGSCAN_SKIP_TABLE_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_skip_table libsigscan_skip_table_t;

struct libsigscan_skip_table
{
	/* The skip pattern size
	 */
	size_t skip_pattern_size;

	/* The skip values
	 */
	size_t skip_values[ 256 ];
};

int libsigscan_skip_table_initialize(
     libsigscan_skip_table_t **skip_table,
     size_t skip_pattern_size,
     libcerror_error_t **error );

int libsigscan_skip_table_free(
     libsigscan_skip_table_t **skip_table,
     libcerror_error_t **error );

/* TODO */
int libsigscan_skip_table_build(
     libsigscan_skip_table_t *skip_table,
     libcerror_error_t **error );

int libsigscan_skip_table_get_skip_value(
     libsigscan_skip_table_t *skip_table,
     uint8_t byte_value,
     size_t *skip_value,
     libcerror_error_t **error );

int libsigscan_skip_table_set_skip_value(
     libsigscan_skip_table_t *skip_table,
     uint8_t byte_value,
     size_t skip_value,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif

