/*
 * Signature definitions
 *
 * Copyright (C) 2014-2015, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _SIGNATURE_DEFINITIONS_H )
#define _SIGNATURE_DEFINITIONS_H

#include <common.h>
#include <types.h>

#include "sigscantools_libcdata.h"
#include "sigscantools_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct signature_definitions signature_definitions_t;

struct signature_definitions
{
	/* The signatures array
	 */
	libcdata_array_t *signatures_array;
};

int signature_definitions_initialize(
     signature_definitions_t **signature_definitions,
     libcerror_error_t **error );

int signature_definitions_free(
     signature_definitions_t **signature_definitions,
     libcerror_error_t **error );

int signature_definitions_read(
     signature_definitions_t *signature_definitions,
     const libcstring_system_character_t *filename,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif

