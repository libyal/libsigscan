/*
 * The signature group functions
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
#include "libsigscan_signature.h"
#include "libsigscan_signature_group.h"

/* Creates a signature group
 * Make sure the value signature_group is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_group_initialize(
     libsigscan_signature_group_t **signature_group,
     uint8_t byte_value,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_group_initialize";

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
	if( *signature_group != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid signature group value already set.",
		 function );

		return( -1 );
	}
	*signature_group = memory_allocate_structure(
	                    libsigscan_signature_group_t );

	if( *signature_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create signature group.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *signature_group,
	     0,
	     sizeof( libsigscan_signature_group_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear signature group.",
		 function );

		memory_free(
		 *signature_group );

		*signature_group = NULL;

		return( -1 );
	}
	if( libcdata_list_initialize(
	     &( ( *signature_group )->signatures_list ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create signatures list.",
		 function );

		goto on_error;
	}
	( *signature_group )->byte_value = byte_value;

	return( 1 );

on_error:
	if( *signature_group != NULL )
	{
		memory_free(
		 *signature_group );

		*signature_group = NULL;
	}
	return( -1 );
}

/* Frees a signature group
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_group_free(
     libsigscan_signature_group_t **signature_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_group_free";
	int result            = 1;

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
	if( *signature_group != NULL )
	{
		/* The signatures in the list are references and freed elsewhere
		 */
		if( libcdata_list_free(
		     &( ( *signature_group )->signatures_list ),
		     NULL,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free signatures list.",
			 function );

			result = -1;
		}
		memory_free(
		 *signature_group );

		*signature_group = NULL;
	}
	return( result );
}

/* Compares two signature groups
 * Returns return LIBCDATA_COMPARE_LESS, LIBCDATA_COMPARE_EQUAL, LIBCDATA_COMPARE_GREATER if successful or -1 on error
 */
int libsigscan_signature_group_compare(
     libsigscan_signature_group_t *first_signature_group,
     libsigscan_signature_group_t *second_signature_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_group_compare";

	if( first_signature_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid first signature group.",
		 function );

		return( -1 );
	}
	if( second_signature_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid second signature group.",
		 function );

		return( -1 );
	}
	if( first_signature_group->byte_value < second_signature_group->byte_value )
	{
		return( LIBCDATA_COMPARE_LESS );
	}
	else if( first_signature_group->byte_value > second_signature_group->byte_value )
	{
		return( LIBCDATA_COMPARE_GREATER );
	}
	return( LIBCDATA_COMPARE_EQUAL );
}

/* Retrieves the byte vlaue
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_group_get_byte_value(
     libsigscan_signature_group_t *signature_group,
     uint8_t *byte_value,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_group_get_byte_value";

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
	if( byte_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte value.",
		 function );

		return( -1 );
	}
	*byte_value = signature_group->byte_value;

	return( 1 );
}

/* Retrieves the number of signatures
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_group_get_number_of_signatures(
     libsigscan_signature_group_t *signature_group,
     int *number_of_signatures,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_group_get_number_of_signatures";

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
	if( libcdata_list_get_number_of_elements(
	     signature_group->signatures_list,
	     number_of_signatures,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of signatures.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a specific signature
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_group_get_signature_by_index(
     libsigscan_signature_group_t *signature_group,
     int signature_index,
     libsigscan_signature_t **signature,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_group_get_signature_by_index";

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
	if( libcdata_list_get_value_by_index(
	     signature_group->signatures_list,
	     signature_index,
	     (intptr_t **) signature,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve signature: %d.",
		 function,
		 signature_index );

		return( -1 );
	}
	return( 1 );
}

/* Appends a signature to the signature group
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_group_append_signature(
     libsigscan_signature_group_t *signature_group,
     libsigscan_signature_t *signature,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_group_append_signature";

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
	if( signature == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature.",
		 function );

		return( -1 );
	}
	if( libcdata_list_append_value(
	     signature_group->signatures_list,
	     (intptr_t *) signature,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to append signature.",
		 function );

		return( -1 );
	}
	return( 1 );
}

