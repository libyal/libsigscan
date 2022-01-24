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

#include <common.h>
#include <memory.h>
#include <types.h>

#include "libsigscan_byte_value_group.h"
#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_signature.h"
#include "libsigscan_signature_group.h"

/* Creates a byte value group
 * Make sure the value byte_value_group is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_byte_value_group_initialize(
     libsigscan_byte_value_group_t **byte_value_group,
     off64_t pattern_offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_byte_value_group_initialize";

	if( byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte value group.",
		 function );

		return( -1 );
	}
	if( *byte_value_group != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid byte value group value already set.",
		 function );

		return( -1 );
	}
	*byte_value_group = memory_allocate_structure(
	                     libsigscan_byte_value_group_t );

	if( *byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create byte value group.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *byte_value_group,
	     0,
	     sizeof( libsigscan_byte_value_group_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear byte value group.",
		 function );

		memory_free(
		 *byte_value_group );

		*byte_value_group = NULL;

		return( -1 );
	}
	if( libcdata_list_initialize(
	     &( ( *byte_value_group )->signature_groups_list ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create signature groups list.",
		 function );

		goto on_error;
	}
	( *byte_value_group )->pattern_offset = pattern_offset;

	return( 1 );

on_error:
	if( *byte_value_group != NULL )
	{
		memory_free(
		 *byte_value_group );

		*byte_value_group = NULL;
	}
	return( -1 );
}

/* Frees a byte value group
 * Returns 1 if successful or -1 on error
 */
int libsigscan_byte_value_group_free(
     libsigscan_byte_value_group_t **byte_value_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_byte_value_group_free";
	int result            = 1;

	if( byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte value group.",
		 function );

		return( -1 );
	}
	if( *byte_value_group != NULL )
	{
		if( libcdata_list_free(
		     &( ( *byte_value_group )->signature_groups_list ),
		     (int (*)(intptr_t **,libcerror_error_t **)) &libsigscan_signature_group_free,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free signature groups list.",
			 function );

			result = -1;
		}
		memory_free(
		 *byte_value_group );

		*byte_value_group = NULL;
	}
	return( result );
}

/* Compares two byte value groups
 * Returns return LIBCDATA_COMPARE_LESS, LIBCDATA_COMPARE_EQUAL, LIBCDATA_COMPARE_GREATER if successful or -1 on error
 */
int libsigscan_byte_value_group_compare(
     libsigscan_byte_value_group_t *first_byte_value_group,
     libsigscan_byte_value_group_t *second_byte_value_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_byte_value_group_compare";

	if( first_byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid first byte value group.",
		 function );

		return( -1 );
	}
	if( second_byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid second byte value group.",
		 function );

		return( -1 );
	}
	if( first_byte_value_group->pattern_offset < second_byte_value_group->pattern_offset )
	{
		return( LIBCDATA_COMPARE_LESS );
	}
	else if( first_byte_value_group->pattern_offset > second_byte_value_group->pattern_offset )
	{
		return( LIBCDATA_COMPARE_GREATER );
	}
	return( LIBCDATA_COMPARE_EQUAL );
}

/* Retrieves the pattern offset
 * Returns 1 if successful or -1 on error
 */
int libsigscan_byte_value_group_get_pattern_offset(
     libsigscan_byte_value_group_t *byte_value_group,
     off64_t *pattern_offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_byte_value_group_get_pattern_offset";

	if( byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte value group.",
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
	*pattern_offset = byte_value_group->pattern_offset;

	return( 1 );
}

/* Retrieves a specific signature group
 * Returns 1 if successful, 0 if no such value or -1 on error
 */
int libsigscan_byte_value_group_get_signature_group(
     libsigscan_byte_value_group_t *byte_value_group,
     uint8_t byte_value,
     libsigscan_signature_group_t **signature_group,
     libcerror_error_t **error )
{
	libcdata_list_element_t *list_element = NULL;
	static char *function                 = "libsigscan_byte_value_group_get_signature_group";
	int result                            = 0;

	if( byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte value group.",
		 function );

		return( -1 );
	}
	if( signature_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature group.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_first_element(
	     byte_value_group->signature_groups_list,
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
		     (intptr_t **) signature_group,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve signature group.",
			 function );

			return( -1 );
		}
		if( *signature_group == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: missing signature group.",
			 function );

			return( -1 );
		}
		if( ( *signature_group )->byte_value == byte_value )
		{
			result = 1;

			break;
		}
		if( ( *signature_group )->byte_value > byte_value )
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
	if( result == 0 )
	{
		*signature_group = NULL;
	}
	return( result );
}

/* Inserts a signature for a specific byte value
 * Returns 1 if successful or -1 on error
 */
int libsigscan_byte_value_group_insert_signature(
     libsigscan_byte_value_group_t *byte_value_group,
     uint8_t byte_value,
     libsigscan_signature_t *signature,
     libcerror_error_t **error )
{
	libsigscan_signature_group_t *signature_group = NULL;
	static char *function                         = "libsigscan_byte_value_group_insert_signature";
	int result                                    = 0;

	if( byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte value group.",
		 function );

		return( -1 );
	}
	result = libsigscan_byte_value_group_get_signature_group(
	          byte_value_group,
	          byte_value,
	          &signature_group,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve byte value group.",
		 function );

		return( -1 );
	}
	else if( result == 0 )
	{
		if( libsigscan_signature_group_initialize(
		     &signature_group,
		     byte_value,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create signature group.",
			 function );

			return( -1 );
		}
		if( libcdata_list_insert_value(
		     byte_value_group->signature_groups_list,
		     (intptr_t *) signature_group,
		     (int (*)(intptr_t *, intptr_t *, libcerror_error_t **)) &libsigscan_signature_group_compare,
		     LIBCDATA_INSERT_FLAG_UNIQUE_ENTRIES,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
			 "%s: unable to insert signature into signature groups list.",
			 function );

			libsigscan_signature_group_free(
			 &signature_group,
			 NULL );

			return( -1 );
		}
	}
	if( libsigscan_signature_group_append_signature(
	     signature_group,
	     signature,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to append signature to signature group.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves the number of signature groups
 * Returns 1 if successful or -1 on error
 */
int libsigscan_byte_value_group_get_number_of_signature_groups(
     libsigscan_byte_value_group_t *byte_value_group,
     int *number_of_signature_groups,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_byte_value_group_get_number_of_signature_groups";

	if( byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte value group.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_number_of_elements(
	     byte_value_group->signature_groups_list,
	     number_of_signature_groups,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of signature groups.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a specific signature group
 * Returns 1 if successful or -1 on error
 */
int libsigscan_byte_value_group_get_signature_group_by_index(
     libsigscan_byte_value_group_t *byte_value_group,
     int signature_group_index,
     libsigscan_signature_group_t **signature_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_byte_value_group_get_signature_group_by_index";

	if( byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte_value group.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_value_by_index(
	     byte_value_group->signature_groups_list,
	     signature_group_index,
	     (intptr_t **) signature_group,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve signature group: %d.",
		 function,
		 signature_group_index );

		return( -1 );
	}
	return( 1 );
}

