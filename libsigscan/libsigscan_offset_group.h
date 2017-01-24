/*
 * The offset group functions
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

#if !defined( _LIBSIGSCAN_OFFSET_GROUP_H )
#define _LIBSIGSCAN_OFFSET_GROUP_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_offset_group libsigscan_offset_group_t;

struct libsigscan_offset_group
{
	/* The weight 
	 */
	int weight;

	/* The offsets array
	 */
	libcdata_array_t *offsets_array;
};

int libsigscan_offset_group_initialize(
     libsigscan_offset_group_t **offset_group,
     int weight,
     libcerror_error_t **error );

int libsigscan_offset_group_free(
     libsigscan_offset_group_t **offset_group,
     libcerror_error_t **error );

int libsigscan_offset_group_compare(
     libsigscan_offset_group_t *first_offset_group,
     libsigscan_offset_group_t *second_offset_group,
     libcerror_error_t **error );

int libsigscan_offset_group_get_weight(
     libsigscan_offset_group_t *offset_group,
     int *weight,
     libcerror_error_t **error );

int libsigscan_offset_group_get_number_of_offsets(
     libsigscan_offset_group_t *offset_group,
     int *number_of_offsets,
     libcerror_error_t **error );

int libsigscan_offset_group_get_offset_by_index(
     libsigscan_offset_group_t *offset_group,
     int offset_index,
     off64_t *pattern_offset,
     libcerror_error_t **error );

int libsigscan_offset_group_append_offset(
     libsigscan_offset_group_t *offset_group,
     off64_t pattern_offset,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_OFFSET_GROUP_H ) */

