/*
 * The weight group functions
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

#if !defined( _LIBSIGSCAN_WEIGHT_GROUP_H )
#define _LIBSIGSCAN_WEIGHT_GROUP_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_weight_group libsigscan_weight_group_t;

struct libsigscan_weight_group
{
	/* The pattern offset
	 */
	off64_t pattern_offset;

	/* The weight
	 */
	int weight;
};

int libsigscan_weight_free(
     int **weight,
     libcerror_error_t **error );

int libsigscan_weight_group_initialize(
     libsigscan_weight_group_t **weight_group,
     off64_t pattern_offset,
     libcerror_error_t **error );

int libsigscan_weight_group_free(
     libsigscan_weight_group_t **weight_group,
     libcerror_error_t **error );

int libsigscan_weight_group_compare(
     libsigscan_weight_group_t *first_weight_group,
     libsigscan_weight_group_t *second_weight_group,
     libcerror_error_t **error );

int libsigscan_weight_group_add_weight(
     libsigscan_weight_group_t *weight_group,
     int weight,
     libcerror_error_t **error );

int libsigscan_weight_group_get_weight(
     libsigscan_weight_group_t *weight_group,
     int *weight,
     libcerror_error_t **error );

int libsigscan_weight_group_set_weight(
     libsigscan_weight_group_t *weight_group,
     int weight,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_WEIGHT_GROUP_H ) */

