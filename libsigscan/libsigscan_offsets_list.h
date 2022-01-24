/*
 * The offsets list functions
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

#if !defined( _LIBSIGSCAN_OFFSETS_LIST_H )
#define _LIBSIGSCAN_OFFSETS_LIST_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

int libsigscan_offset_free(
     off64_t **offset,
     libcerror_error_t **error );

int libsigscan_offset_clone(
     off64_t **destination_offset,
     off64_t *source_offset,
     libcerror_error_t **error );

int libsigscan_offset_list_compare(
     off64_t *first_offset,
     off64_t *second_offset,
     libcerror_error_t **error );

int libsigscan_offsets_list_has_offset(
     libcdata_list_t *offsets_list,
     off64_t pattern_offset,
     libcerror_error_t **error );

int libsigscan_offsets_list_insert_offset(
     libcdata_list_t *offsets_list,
     off64_t pattern_offset,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_OFFSETS_LIST_H ) */

