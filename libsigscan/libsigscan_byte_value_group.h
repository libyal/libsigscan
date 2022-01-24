/*
 * The byte value group functions
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

#if !defined( _LIBSIGSCAN_BYTE_VALUE_GROUP_H )
#define _LIBSIGSCAN_BYTE_VALUE_GROUP_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_signature.h"
#include "libsigscan_signature_group.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_byte_value_group libsigscan_byte_value_group_t;

struct libsigscan_byte_value_group
{
	/* The pattern offset
	 */
	off64_t pattern_offset;

	/* The signature groups list sorted by byte value
	 */
	libcdata_list_t *signature_groups_list;
};

int libsigscan_byte_value_group_initialize(
     libsigscan_byte_value_group_t **byte_value_group,
     off64_t pattern_offset,
     libcerror_error_t **error );

int libsigscan_byte_value_group_free(
     libsigscan_byte_value_group_t **byte_value_group,
     libcerror_error_t **error );

int libsigscan_byte_value_group_compare(
     libsigscan_byte_value_group_t *first_byte_value_group,
     libsigscan_byte_value_group_t *second_byte_value_group,
     libcerror_error_t **error );

int libsigscan_byte_value_group_get_pattern_offset(
     libsigscan_byte_value_group_t *byte_value_group,
     off64_t *pattern_offset,
     libcerror_error_t **error );

int libsigscan_byte_value_group_get_signature_group(
     libsigscan_byte_value_group_t *byte_value_group,
     uint8_t byte_value,
     libsigscan_signature_group_t **signature_group,
     libcerror_error_t **error );

int libsigscan_byte_value_group_insert_signature(
     libsigscan_byte_value_group_t *byte_value_group,
     uint8_t byte_value,
     libsigscan_signature_t *signature,
     libcerror_error_t **error );

int libsigscan_byte_value_group_get_number_of_signature_groups(
     libsigscan_byte_value_group_t *byte_value_group,
     int *number_of_signature_groups,
     libcerror_error_t **error );

int libsigscan_byte_value_group_get_signature_group_by_index(
     libsigscan_byte_value_group_t *byte_value_group,
     int signature_group_index,
     libsigscan_signature_group_t **signature_group,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_BYTE_VALUE_GROUP_H ) */

