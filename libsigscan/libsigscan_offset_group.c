/*
 * The offset group functions
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

#include <common.h>
#include <memory.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_offset_group.h"
#include "libsigscan_offsets_list.h"

/* Creates an offset group
 * Make sure the value offset_group is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offset_group_initialize(
     libsigscan_offset_group_t **offset_group,
     int weight,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_group_initialize";

	if( offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset group.",
		 function );

		return( -1 );
	}
	if( *offset_group != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid offset group value already set.",
		 function );

		return( -1 );
	}
	*offset_group = memory_allocate_structure(
	                 libsigscan_offset_group_t );

	if( *offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create offset group.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *offset_group,
	     0,
	     sizeof( libsigscan_offset_group_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear offset group.",
		 function );

		memory_free(
		 *offset_group );

		*offset_group = NULL;

		return( -1 );
	}
	if( libcdata_array_initialize(
	     &( ( *offset_group )->offsets_array ),
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create offsets array.",
		 function );

		goto on_error;
	}
	( *offset_group )->weight = weight;

	return( 1 );

on_error:
	if( *offset_group != NULL )
	{
		memory_free(
		 *offset_group );

		*offset_group = NULL;
	}
	return( -1 );
}

/* Frees an offset group
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offset_group_free(
     libsigscan_offset_group_t **offset_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_group_free";
	int result            = 1;

	if( offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset group.",
		 function );

		return( -1 );
	}
	if( *offset_group != NULL )
	{
		if( libcdata_array_free(
		     &( ( *offset_group )->offsets_array ),
		     (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_offset_free,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free offsets array.",
			 function );

			result = -1;
		}
		memory_free(
		 *offset_group );

		*offset_group = NULL;
	}
	return( result );
}

/* Compares two offset groups
 * Returns return LIBCDATA_COMPARE_LESS, LIBCDATA_COMPARE_EQUAL, LIBCDATA_COMPARE_GREATER if successful or -1 on error
 */
int libsigscan_offset_group_compare(
     libsigscan_offset_group_t *first_offset_group,
     libsigscan_offset_group_t *second_offset_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_group_compare";

	if( first_offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid first offset group.",
		 function );

		return( -1 );
	}
	if( second_offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid second offset group.",
		 function );

		return( -1 );
	}
	if( first_offset_group->weight < second_offset_group->weight )
	{
		return( LIBCDATA_COMPARE_LESS );
	}
	else if( first_offset_group->weight > second_offset_group->weight )
	{
		return( LIBCDATA_COMPARE_GREATER );
	}
	return( LIBCDATA_COMPARE_EQUAL );
}

/* Retrieves the weight
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offset_group_get_weight(
     libsigscan_offset_group_t *offset_group,
     int *weight,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_group_get_weight";

	if( offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset group.",
		 function );

		return( -1 );
	}
	if( weight == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid weight.",
		 function );

		return( -1 );
	}
	*weight = offset_group->weight;

	return( 1 );
}

/* Retrieves the number of offsets
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offset_group_get_number_of_offsets(
     libsigscan_offset_group_t *offset_group,
     int *number_of_offsets,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_group_get_number_of_offsets";

	if( offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset group.",
		 function );

		return( -1 );
	}
	if( libcdata_array_get_number_of_entries(
	     offset_group->offsets_array,
	     number_of_offsets,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of offsets.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a specific offset
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offset_group_get_offset_by_index(
     libsigscan_offset_group_t *offset_group,
     int offset_index,
     off64_t *pattern_offset,
     libcerror_error_t **error )
{
	off64_t *offset_value = NULL;
	static char *function = "libsigscan_offset_group_get_offset_by_index";

	if( offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset group.",
		 function );

		return( -1 );
	}
	if( pattern_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern offset.",
		 function );

		return( -1 );
	}
	if( libcdata_array_get_entry_by_index(
	     offset_group->offsets_array,
	     offset_index,
	     (intptr_t **) &offset_value,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve offset: %d.",
		 function,
		 offset_index );

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
	*pattern_offset = *offset_value;

	return( 1 );
}

/* Appends an offset to the offset group
 * Returns 1 if successful or -1 on error
 */
int libsigscan_offset_group_append_offset(
     libsigscan_offset_group_t *offset_group,
     off64_t pattern_offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_offset_group_append_offset";
	off64_t *offset_value = NULL;
	int entry_index       = 0;

	if( offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset group.",
		 function );

		return( -1 );
	}
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

	if( libcdata_array_append_entry(
	     offset_group->offsets_array,
	     &entry_index,
	     (intptr_t *) offset_value,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to append offset.",
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

