/*
 * Pattern weights functions
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

#if !defined( _LIBSIGSCAN_PATTERN_WEIGHTS_H )
#define _LIBSIGSCAN_PATTERN_WEIGHTS_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_offset_group.h"
#include "libsigscan_weight_group.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_pattern_weights libsigscan_pattern_weights_t;

struct libsigscan_pattern_weights
{
	/* The offsets (per weight) groups list
	 */
	libcdata_list_t *offset_groups_list;

	/* The weight (per offset) groups list
	 */
	libcdata_list_t *weight_groups_list;
};

int libsigscan_pattern_weights_initialize(
     libsigscan_pattern_weights_t **pattern_weights,
     libcerror_error_t **error );

int libsigscan_pattern_weights_free(
     libsigscan_pattern_weights_t **pattern_weights,
     libcerror_error_t **error );

int libsigscan_pattern_weights_add_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error );

int libsigscan_pattern_weights_set_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error );

int libsigscan_pattern_weights_get_largest_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     int *largest_weight,
     libcerror_error_t **error );

int libsigscan_pattern_weights_get_offset_group(
     libsigscan_pattern_weights_t *pattern_weights,
     int weight,
     libsigscan_offset_group_t **offset_group,
     libcerror_error_t **error );

int libsigscan_pattern_weights_insert_offset(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error );

int libsigscan_pattern_weights_get_weight_group(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     libsigscan_weight_group_t **weight_group,
     libcerror_error_t **error );

int libsigscan_pattern_weights_insert_add_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error );

int libsigscan_pattern_weights_insert_set_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_PATTERN_WEIGHTS_H ) */

