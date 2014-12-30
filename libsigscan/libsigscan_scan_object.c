/*
 * Scan object functions
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

#include <common.h>
#include <memory.h>
#include <types.h>

#include "libsigscan_definitions.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_scan_object.h"

/* Creates scan object
 * Make sure the value scan_object is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_object_initialize(
     libsigscan_scan_object_t **scan_object,
     uint8_t type,
     intptr_t *value,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_object_initialize";

	if( scan_object == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan object.",
		 function );

		return( -1 );
	}
	if( *scan_object != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan object value already set.",
		 function );

		return( -1 );
	}
	if( ( type != LIBSIGSCAN_SCAN_OBJECT_TYPE_SCAN_TREE_NODE )
	 && ( type != LIBSIGSCAN_SCAN_OBJECT_TYPE_SIGNATURE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported type.",
		 function );

		return( -1 );
	}
	if( value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid value.",
		 function );

		return( -1 );
	}
	*scan_object = memory_allocate_structure(
	                libsigscan_scan_object_t );

	if( *scan_object == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan object.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *scan_object,
	     0,
	     sizeof( libsigscan_scan_object_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear scan object.",
		 function );

		memory_free(
		 *scan_object );

		*scan_object = NULL;

		return( -1 );
	}
	( *scan_object )->type  = type;
	( *scan_object )->value = value;

	return( 1 );

on_error:
	if( *scan_object != NULL )
	{
		memory_free(
		 *scan_object );

		*scan_object = NULL;
	}
	return( -1 );
}

/* Frees scan object
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_object_free(
     libsigscan_scan_object_t **scan_object,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_object_free";

	if( scan_object == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan object.",
		 function );

		return( -1 );
	}
	if( *scan_object != NULL )
	{
		memory_free(
		 *scan_object );

		*scan_object = NULL;
	}
	return( 1 );
}

