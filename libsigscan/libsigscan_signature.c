/*
 * Signature functions
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

#include "libsigscan_definitions.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_signature.h"

/* Creates a signature
 * Make sure the value signature is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_initialize(
     libsigscan_signature_t **signature,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_initialize";

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
	if( *signature != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid signature value already set.",
		 function );

		return( -1 );
	}
	*signature = memory_allocate_structure(
	              libsigscan_signature_t );

	if( *signature == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create signature.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *signature,
	     0,
	     sizeof( libsigscan_signature_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear signature.",
		 function );

		memory_free(
		 *signature );

		*signature = NULL;

		return( -1 );
	}
	( *signature )->pattern_offset = -1;

	return( 1 );

on_error:
	if( *signature != NULL )
	{
		memory_free(
		 *signature );

		*signature = NULL;
	}
	return( -1 );
}

/* Frees a signature
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_free(
     libsigscan_signature_t **signature,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_free";

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
	if( *signature != NULL )
	{
		if( ( *signature )->identifier != NULL )
		{
			memory_free(
			 ( *signature )->identifier );
		}
		if( ( *signature )->pattern != NULL )
		{
			memory_free(
			 ( *signature )->pattern );
		}
		memory_free(
		 *signature );

		*signature = NULL;
	}
	return( 1 );
}

/* Frees a signature clone
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_free_clone(
     libsigscan_signature_t **signature,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_free_clone";

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
	if( *signature != NULL )
	{
		*signature = NULL;
	}
	return( 1 );
}

/* Clones a signature
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_clone(
     libsigscan_signature_t **destination_signature,
     libsigscan_signature_t *source_signature,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_clone";

	if( destination_signature == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid destination signature.",
		 function );

		return( -1 );
	}
	if( *destination_signature != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid destination signature value already set.",
		 function );

		return( -1 );
	}
	/* Clone by reference
	 */
	*destination_signature = source_signature;

	return( 1 );
}

/* Sets the signature values
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_set(
     libsigscan_signature_t *signature,
     const char *identifier,
     size_t identifier_length,
     off64_t pattern_offset,
     const uint8_t *pattern,
     size_t pattern_size,
     uint32_t signature_flags,
     libcerror_error_t **error )
{
	static char *function    = "libsigscan_signature_set";
	uint32_t supported_flags = 0;

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
	if( ( identifier_length == 0 )
	 || ( identifier_length > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid identifier length value out of bounds.",
		 function );

		return( -1 );
	}
	if( pattern == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern.",
		 function );

		return( -1 );
	}
	if( ( pattern_size == 0 )
	 || ( pattern_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid pattern size value out of bounds.",
		 function );

		return( -1 );
	}
	supported_flags = LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START
	                | LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_END;

	if( ( signature_flags & ~supported_flags ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported signature flags.",
		 function );

		return( -1 );
	}
	if( signature->identifier != NULL )
	{
		memory_free(
		 signature->identifier );

		signature->identifier      = NULL;
		signature->identifier_size = 0;
	}
	if( signature->pattern != NULL )
	{
		memory_free(
		 signature->pattern );

		signature->pattern      = NULL;
		signature->pattern_size = 0;
	}
	if( identifier[ identifier_length - 1 ] != 0 )
	{
		identifier_length += 1;
	}
	signature->identifier = (char *) memory_allocate(
	                                  sizeof( char ) * identifier_length );

	if( signature->identifier == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create identifier.",
		 function );

		goto on_error;
	}
	signature->identifier_size = identifier_length;

	if( memory_copy(
	     signature->identifier,
	     identifier,
	     signature->identifier_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy identifier.",
		 function );

		goto on_error;
	}
	signature->pattern_offset = pattern_offset;

	signature->pattern = (uint8_t *) memory_allocate(
	                                  sizeof( uint8_t ) * pattern_size );

	if( signature->pattern == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create pattern.",
		 function );

		goto on_error;
	}
	signature->pattern_size = pattern_size;

	if( memory_copy(
	     signature->pattern,
	     pattern,
	     pattern_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy pattern.",
		 function );

		goto on_error;
	}
	signature->signature_flags = signature_flags;

	return( 1 );

on_error:
	if( signature->pattern != NULL )
	{
		memory_free(
		 signature->pattern );

		signature->pattern      = NULL;
		signature->pattern_size = 0;
	}
	if( signature->identifier != NULL )
	{
		memory_free(
		 signature->identifier );

		signature->identifier      = NULL;
		signature->identifier_size = 0;
	}
	return( -1 );
}

/* Retrieves the size of the identifier
 * The returned size includes the end of string character
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_get_identifier_size(
     libsigscan_signature_t *signature,
     size_t *identifier_size,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_get_identifier_size";

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
	if( identifier_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid identifier size.",
		 function );

		return( -1 );
	}
	*identifier_size = signature->identifier_size;

	return( 1 );
}

/* Retrieves the identifier
 * The size should include the end of string character
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_get_identifier(
     libsigscan_signature_t *signature,
     char *identifier,
     size_t identifier_size,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_get_identifier";

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
	if( identifier_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid identifier size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( identifier_size < signature->identifier_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid identifier value too small.",
		 function );

		return( -1 );
	}
	if( memory_copy(
	     identifier,
	     signature->identifier,
	     signature->identifier_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy identifier.",
		 function );

		return( -1 );
	}
	return( 1 );
}

