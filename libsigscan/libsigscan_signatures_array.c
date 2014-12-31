/*
 * The signatures array functions
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
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_signature.h"
#include "libsigscan_signatures_array.h"

/* Retrieves the number of signatures
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signatures_array_get_number_of_signatures(
     libcdata_array_t *signatures_array,
     int *number_of_signatures,
     libcerror_error_t **error )
{
	libsigscan_signature_t *signature_entry = NULL;
	static char *function                   = "libsigscan_signatures_array_remove_signature";
	int number_of_signature_entries         = 0;
	int signature_entry_index               = 0;

	if( number_of_signatures == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid number of signatures.",
		 function );

		return( -1 );
	}
	*number_of_signatures = 0;

	if( libcdata_array_get_number_of_entries(
	     signatures_array,
	     &number_of_signature_entries,
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
	for( signature_entry_index = 0;
	     signature_entry_index < number_of_signature_entries;
	     signature_entry_index++ )
	{
		if( libcdata_array_get_entry_by_index(
		     signatures_array,
		     signature_entry_index,
		     (intptr_t **) &signature_entry,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve signature: %d.",
			 function,
			 signature_entry_index );

			return( -1 );
		}
		if( signature_entry == NULL )
		{
			continue;
		}
		*number_of_signatures += 1;
	}
	return( 1 );
}

/* Removes a signature from the array
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signatures_array_remove_signature(
     libcdata_array_t *signatures_array,
     libsigscan_signature_t *signature,
     libcerror_error_t **error )
{
	libsigscan_signature_t *signature_entry = NULL;
	static char *function                   = "libsigscan_signatures_array_remove_signature";
	int number_of_signature_entries         = 0;
	int signature_entry_index               = 0;

	if( libcdata_array_get_number_of_entries(
	     signatures_array,
	     &number_of_signature_entries,
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
	for( signature_entry_index = 0;
	     signature_entry_index < number_of_signature_entries;
	     signature_entry_index++ )
	{
		if( libcdata_array_get_entry_by_index(
		     signatures_array,
		     signature_entry_index,
		     (intptr_t **) &signature_entry,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve signature: %d.",
			 function,
			 signature_entry_index );

			return( -1 );
		}
		if( signature_entry == NULL )
		{
			continue;
		}
		/* Using a pointer comparison here since the signatures are cloned by reference
		 */
		if( signature != signature_entry )
		{
			if( libcdata_array_set_entry_by_index(
			     signatures_array,
			     signature_entry_index,
			     (intptr_t *) NULL,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
				 "%s: unable to set signature: %d.",
				 function,
				 signature_entry_index );

				return( -1 );
			}
			break;
		}
	}
	return( 1 );
}

