/*
 * The offsets list functions
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

#include <common.h>
#include <memory.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_offsets_list.h"

/* Frees an offset
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offset_free(
     off64_t **offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_free";

	if( offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset.",
		 function );

		return( -1 );
	}
	if( *offset != NULL )
	{
		memory_free(
		 *offset );

		*offset = NULL;
	}
	return( 1 );
}

/* Clones an offset
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offset_clone(
     off64_t **destination_offset,
     off64_t *source_offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_clone";

	if( destination_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid destination offset.",
		 function );

		return( -1 );
	}
	if( *destination_offset != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid destination offset value already set.",
		 function );

		return( -1 );
	}
	if( source_offset == NULL )
	{
		*destination_offset = NULL;

		return( 1 );
	}
	*destination_offset = (off64_t *) memory_allocate(
	                                   sizeof( off64_t ) );

	if( *destination_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create destination offset.",
		 function );

		return( -1 );
	}
	**destination_offset = *source_offset;

	return( 1 );
}

/* Compares two offsets
 * Returns return LIBCDATA_COMPARE_LESS, LIBCDATA_COMPARE_EQUAL, LIBCDATA_COMPARE_GREATER if successful or -1 on error
 */
int libsigscan_offset_list_compare(
     off64_t *first_offset,
     off64_t *second_offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_list_compare";

	if( first_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid first offset.",
		 function );

		return( -1 );
	}
	if( second_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid second offset.",
		 function );

		return( -1 );
	}
	if( *first_offset < *second_offset )
	{
		return( LIBCDATA_COMPARE_LESS );
	}
	else if( *first_offset > *second_offset )
	{
		return( LIBCDATA_COMPARE_GREATER );
	}
	return( LIBCDATA_COMPARE_EQUAL );
}

/* Determines if the offset list contains a specific pattern offset
 * Returns 1 if successful, 0 if not or -1 on error
 */
int libsigscan_offsets_list_has_offset(
     libcdata_list_t *offsets_list,
     off64_t pattern_offset,
     libcerror_error_t **error )
{
	libcdata_list_element_t *list_element = NULL;
	off64_t *offset_value                 = NULL;
	static char *function                 = "libsigscan_offsets_list_has_offset";
	int result                            = 0;

	if( libcdata_list_get_first_element(
	     offsets_list,
	     &list_element,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve first list element.",
		 function );

		return( -1 );
	}
	while( list_element != NULL )
	{
		if( libcdata_list_element_get_value(
		     list_element,
		     (intptr_t **) &offset_value,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve offset value.",
			 function );

			return( -1 );
		}
		if( offset_value == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: missing offset value.",
			 function );

			return( -1 );
		}
		if( *offset_value == pattern_offset )
		{
			result = 1;

			break;
		}
		else if( *offset_value > pattern_offset )
		{
			break;
		}
		if( libcdata_list_element_get_next_element(
		     list_element,
		     &list_element,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve next list element.",
			 function );

			return( -1 );
		}
	}
	return( result );
}

/* Inserts a pattern offset
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offsets_list_insert_offset(
     libcdata_list_t *offsets_list,
     off64_t pattern_offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offsets_list_insert_offset";
	off64_t *offset_value = NULL;

	offset_value = (off64_t *) memory_allocate(
	                            sizeof( off64_t ) );

	if( offset_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create offset value.",
		 function );

		goto on_error;
	}
	*offset_value = pattern_offset;

	if( libcdata_list_insert_value(
	     offsets_list,
	     (intptr_t *) offset_value,
	     (int (*)(intptr_t *, intptr_t *, libcerror_error_t **)) &libsigscan_offset_list_compare,
	     LIBCDATA_INSERT_FLAG_UNIQUE_ENTRIES,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to insert offset.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( offset_value != NULL )
	{
		memory_free(
		 offset_value );
	}
	return( -1 );
}

