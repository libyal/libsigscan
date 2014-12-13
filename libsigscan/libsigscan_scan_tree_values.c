/*
 * Signature functions
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

#include "libsigscan_libcerror.h"
#include "libsigscan_scan_tree_values.h"

/* Creates scan tree values
 * Make sure the value scan_tree_values is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_values_initialize(
     libsigscan_scan_tree_values_t **scan_tree_values,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_values_initialize";

	if( scan_tree_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree values.",
		 function );

		return( -1 );
	}
	if( *scan_tree_values != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan tree values value already set.",
		 function );

		return( -1 );
	}
	*scan_tree_values = memory_allocate_structure(
	                     libsigscan_scan_tree_values_t );

	if( *scan_tree_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan tree values.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *scan_tree_values,
	     0,
	     sizeof( libsigscan_scan_tree_values_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear scan tree values.",
		 function );

		memory_free(
		 *scan_tree_values );

		*scan_tree_values = NULL;

		return( -1 );
	}
	return( 1 );

on_error:
	if( *scan_tree_values != NULL )
	{
		memory_free(
		 *scan_tree_values );

		*scan_tree_values = NULL;
	}
	return( -1 );
}

/* Frees scan tree values
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_values_free(
     libsigscan_scan_tree_values_t **scan_tree_values,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_values_free";

	if( scan_tree_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree values.",
		 function );

		return( -1 );
	}
	if( *scan_tree_values != NULL )
	{
		memory_free(
		 *scan_tree_values );

		*scan_tree_values = NULL;
	}
	return( 1 );
}

