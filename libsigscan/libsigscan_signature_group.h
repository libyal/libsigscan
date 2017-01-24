/*
 * The signature group functions
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

#if !defined( _LIBSIGSCAN_SIGNATURE_GROUP_H )
#define _LIBSIGSCAN_SIGNATURE_GROUP_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_signature.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_signature_group libsigscan_signature_group_t;

struct libsigscan_signature_group
{
	/* The byte value
	 */
	uint8_t byte_value;

	/* The signatures list
	 */
	libcdata_list_t *signatures_list;
};

int libsigscan_signature_group_initialize(
     libsigscan_signature_group_t **signature_group,
     uint8_t byte_value,
     libcerror_error_t **error );

int libsigscan_signature_group_free(
     libsigscan_signature_group_t **signature_group,
     libcerror_error_t **error );

int libsigscan_signature_group_compare(
     libsigscan_signature_group_t *first_signature_group,
     libsigscan_signature_group_t *second_signature_group,
     libcerror_error_t **error );

int libsigscan_signature_group_get_byte_value(
     libsigscan_signature_group_t *signature_group,
     uint8_t *byte_value,
     libcerror_error_t **error );

int libsigscan_signature_group_get_number_of_signatures(
     libsigscan_signature_group_t *signature_group,
     int *number_of_signatures,
     libcerror_error_t **error );

int libsigscan_signature_group_get_signature_by_index(
     libsigscan_signature_group_t *signature_group,
     int signature_index,
     libsigscan_signature_t **signature,
     libcerror_error_t **error );

int libsigscan_signature_group_append_signature(
     libsigscan_signature_group_t *signature_group,
     libsigscan_signature_t *signature,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_SIGNATURE_GROUP_H ) */

