/*
 * Identifier functions
 *
 * Copyright (C) 2014-2024, Joachim Metz <joachim.metz@gmail.com>
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

#include "libsigscan_identifier.h"
#include "libsigscan_libcerror.h"

/* Creates a identifier
 * Make sure the value identifier is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_identifier_initialize(
     libsigscan_identifier_t **identifier,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_identifier_initialize";

	if( identifier == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid identifier.",
		 function );

		return( -1 );
	}
	if( *identifier != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid identifier value already set.",
		 function );

		return( -1 );
	}
	*identifier = memory_allocate_structure(
	               libsigscan_identifier_t );

	if( *identifier == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create identifier.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *identifier,
	     0,
	     sizeof( libsigscan_identifier_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear identifier.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *identifier != NULL )
	{
		memory_free(
		 *identifier );

		*identifier = NULL;
	}
	return( -1 );
}

/* Frees a identifier
 * Returns 1 if successful or -1 on error
 */
int libsigscan_identifier_free(
     libsigscan_identifier_t **identifier,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_identifier_free";

	if( identifier == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid identifier.",
		 function );

		return( -1 );
	}
	if( *identifier != NULL )
	{
		if( ( *identifier )->string != NULL )
		{
			memory_free(
			 ( *identifier )->string );
		}
		memory_free(
		 *identifier );

		*identifier = NULL;
	}
	return( 1 );
}

/* Retrieves the size of the string
 * The returned size includes the end of string character
 * Returns 1 if successful or -1 on error
 */
int libsigscan_identifier_get_string_size(
     libsigscan_identifier_t *identifier,
     size_t *string_size,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_identifier_get_string_size";

	if( identifier == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid identifier.",
		 function );

		return( -1 );
	}
	if( string_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string size.",
		 function );

		return( -1 );
	}
	*string_size = identifier->string_size;

	return( 1 );
}

/* Retrieves the string
 * The size should include the end of string character
 * Returns 1 if successful or -1 on error
 */
int libsigscan_identifier_get_string(
     libsigscan_identifier_t *identifier,
     char *string,
     size_t string_size,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_identifier_get_string";

	if( identifier == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid identifier.",
		 function );

		return( -1 );
	}
	if( string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string.",
		 function );

		return( -1 );
	}
	if( string_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid string size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( string_size < identifier->string_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid string value too small.",
		 function );

		return( -1 );
	}
	if( memory_copy(
	     string,
	     identifier->string,
	     identifier->string_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy string.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Sets the identifier values
 * Returns 1 if successful or -1 on error
 */
int libsigscan_identifier_set(
     libsigscan_identifier_t *identifier,
     const char *string,
     size_t string_length,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_identifier_set";

	if( identifier == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid identifier.",
		 function );

		return( -1 );
	}
	if( identifier->string != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid identifier - string value already set.",
		 function );

		return( -1 );
	}
	if( string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string.",
		 function );

		return( -1 );
	}
	if( ( string_length == 0 )
	 || ( string_length > (size_t) MEMORY_MAXIMUM_ALLOCATION_SIZE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid string length value out of bounds.",
		 function );

		return( -1 );
	}
	if( string[ string_length - 1 ] != 0 )
	{
		string_length += 1;
	}
	identifier->string = (char *) memory_allocate(
	                               sizeof( char ) * string_length );

	if( identifier->string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create string.",
		 function );

		goto on_error;
	}
	identifier->string_size = string_length;

	if( memory_copy(
	     identifier->string,
	     string,
	     identifier->string_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy string.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( identifier->string != NULL )
	{
		memory_free(
		 identifier->string );

		identifier->string      = NULL;
		identifier->string_size = 0;
	}
	return( -1 );
}

