/*
 * Signature functions
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

#include "libsigscan_definitions.h"
#include "libsigscan_identifier.h"
#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_libcnotify.h"
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
	if( libcdata_list_initialize(
	     &( ( *signature )->identifiers_list ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create identifiers list.",
		 function );

		goto on_error;
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
	int result            = 1;

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
		if( libcdata_list_free(
		     &( ( *signature )->identifiers_list ),
		     (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_identifier_free,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free identifiers list.",
			 function );

			result = -1;
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
	return( result );
}

/* Frees a signature reference clone
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_free_reference_clone(
     libsigscan_signature_t **signature,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_free_reference_clone";

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

/* Clones a signature by reference
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_clone_by_reference(
     libsigscan_signature_t **destination_signature,
     libsigscan_signature_t *source_signature,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_clone_by_reference";

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

/* Compares the patterns of two signatures
 * Returns return LIBCDATA_COMPARE_LESS, LIBCDATA_COMPARE_EQUAL, LIBCDATA_COMPARE_GREATER if successful or -1 on error
 */
int libsigscan_signature_compare_by_pattern(
     libsigscan_signature_t *first_signature,
     libsigscan_signature_t *second_signature,
     libcerror_error_t **error )
{
	static char *function        = "libsigscan_signature_compare_by_pattern";
	size_t smallest_pattern_size = 0;
	int result                   = 0;

	if( first_signature == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid first signature.",
		 function );

		return( -1 );
	}
	if( first_signature->pattern == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid first signature - missing pattern.",
		 function );

		return( -1 );
	}
	if( second_signature == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid second signature.",
		 function );

		return( -1 );
	}
	if( second_signature->pattern == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid second signature - missing pattern.",
		 function );

		return( -1 );
	}
	if( first_signature->pattern_offset < second_signature->pattern_offset )
	{
		return( LIBCDATA_COMPARE_LESS );
	}
	else if( first_signature->pattern_offset > second_signature->pattern_offset )
	{
		return( LIBCDATA_COMPARE_GREATER );
	}
	if( first_signature->pattern_size <= second_signature->pattern_size )
	{
		smallest_pattern_size = first_signature->pattern_size;
	}
	else
	{
		smallest_pattern_size = second_signature->pattern_size;
	}
/* TODO compare signature_flags */

	result = memory_compare(
	          first_signature->pattern,
	          second_signature->pattern,
	          smallest_pattern_size );

	if( result < 0 )
	{
		return( LIBCDATA_COMPARE_LESS );
	}
	else if( result > 0 )
	{
		return( LIBCDATA_COMPARE_GREATER );
	}
	if( first_signature->pattern_size < second_signature->pattern_size )
	{
		return( LIBCDATA_COMPARE_LESS );
	}
	else if( first_signature->pattern_size > second_signature->pattern_size )
	{
		return( LIBCDATA_COMPARE_GREATER );
	}
	return( LIBCDATA_COMPARE_EQUAL );
}

/* Retrieves the number of identifiers
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_get_number_of_identifiers(
     libsigscan_signature_t *signature,
     int *number_of_identifiers,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_get_number_of_identifiers";

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
	if( libcdata_list_get_number_of_elements(
	     signature->identifiers_list,
	     number_of_identifiers,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of elements of identifiers list.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves the size of the identifier
 * The returned size includes the end of string character
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_get_identifier_size(
     libsigscan_signature_t *signature,
     int identifier_index,
     size_t *identifier_size,
     libcerror_error_t **error )
{
	libsigscan_identifier_t *safe_identifier = NULL;
	static char *function                    = "libsigscan_signature_get_identifier_size";

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
	if( libcdata_list_get_value_by_index(
	     signature->identifiers_list,
	     identifier_index,
	     (intptr_t **) &safe_identifier,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve identifier: %d.",
		 function,
		 identifier_index );

		return( -1 );
	}
	if( libsigscan_identifier_get_string_size(
	     safe_identifier,
	     identifier_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve identifier: %d string size.",
		 function,
		 identifier_index );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves the identifier
 * The size should include the end of string character
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_get_identifier(
     libsigscan_signature_t *signature,
     int identifier_index,
     char *identifier,
     size_t identifier_size,
     libcerror_error_t **error )
{
	libsigscan_identifier_t *safe_identifier = NULL;
	static char *function                    = "libsigscan_signature_get_identifier";

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
	if( libcdata_list_get_value_by_index(
	     signature->identifiers_list,
	     identifier_index,
	     (intptr_t **) &safe_identifier,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve identifier: %d.",
		 function,
		 identifier_index );

		return( -1 );
	}
	if( libsigscan_identifier_get_string(
	     safe_identifier,
	     identifier,
	     identifier_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve identifier: %d string.",
		 function,
		 identifier_index );

		return( -1 );
	}
	return( 1 );
}

/* Appends an identifier
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_append_identifier(
     libsigscan_signature_t *signature,
     const char *identifier,
     size_t identifier_length,
     libcerror_error_t **error )
{
	libsigscan_identifier_t *safe_identifier = NULL;
	static char *function                    = "libsigscan_signature_append_identifier";

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
	if( libsigscan_identifier_initialize(
	     &safe_identifier,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create identifier.",
		 function );

		goto on_error;
	}
	if( libsigscan_identifier_set(
	     safe_identifier,
	     identifier,
	     identifier_length,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set identifier.",
		 function );

		goto on_error;
	}
	if( libcdata_list_append_value(
	     signature->identifiers_list,
	     (intptr_t *) safe_identifier,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to append identifier.",
		 function );

		goto on_error;
	}
	if( signature->identifier == NULL )
	{
		signature->identifier      = safe_identifier->string;
		signature->identifier_size = safe_identifier->string_size;
	}
	return( 1 );

on_error:
	if( safe_identifier != NULL )
	{
		libsigscan_identifier_free(
		 &safe_identifier,
		 NULL );
	}
	return( -1 );
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
	if( signature->pattern != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid signature - pattern value already set.",
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
	 || ( pattern_size > (size_t) MEMORY_MAXIMUM_ALLOCATION_SIZE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
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
	signature->pattern_offset  = pattern_offset;
	signature->pattern_size    = pattern_size;
	signature->signature_flags = signature_flags;

	if( libsigscan_signature_append_identifier(
	     signature,
	     identifier,
	     identifier_length,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to append identifier.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( signature->pattern != NULL )
	{
		memory_free(
		 signature->pattern );

		signature->pattern      = NULL;
		signature->pattern_size = 0;
	}
	libcdata_list_empty(
	 signature->identifiers_list,
	 (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_identifier_free,
	 NULL );

	signature->identifier      = NULL;
	signature->identifier_size = 0;

	return( -1 );
}

/* Checks if the signature matches the contents of the buffer
 * Returns 1 if successful, 0 if not or -1 on error
 */
int libsigscan_signature_scan_buffer(
     libsigscan_signature_t *signature,
     int pattern_offsets_mode,
     off64_t data_offset,
     size64_t data_size,
     const uint8_t *buffer,
     size_t buffer_size,
     size_t buffer_offset,
     libcerror_error_t **error )
{
	static char *function  = "libsigscan_signature_scan_buffer";
	off64_t pattern_offset = 0;
	off64_t scan_offset    = 0;

	if( signature == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: missing signature.",
		 function );

		return( -1 );
	}
	if( ( pattern_offsets_mode != LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START )
	 && ( pattern_offsets_mode != LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_END )
	 && ( pattern_offsets_mode != LIBSIGSCAN_PATTERN_OFFSET_MODE_UNBOUND ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported pattern offsets mode.",
		 function );

		return( -1 );
	}
	if( ( data_offset < 0 )
	 || ( (size64_t) data_offset >= data_size ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid data offset value out of bounds.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( buffer_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid buffer size value exceeds maximum.",
		 function );

		return( -1 );
	}
	switch( pattern_offsets_mode )
	{
		case LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START:
			pattern_offset = signature->pattern_offset;
			scan_offset = buffer_offset + ( pattern_offset - data_offset );
			break;

		case LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_END:
			pattern_offset = data_size - signature->pattern_offset;
			scan_offset = buffer_offset + ( pattern_offset - data_offset );
			break;

		case LIBSIGSCAN_PATTERN_OFFSET_MODE_UNBOUND:
			pattern_offset = data_offset;
			scan_offset = buffer_offset;
			break;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: scanning for signature: %s at offset: %" PRIi64 " of size: %" PRIzd ".\n",
		 function,
		 signature->identifier,
		 pattern_offset,
		 signature->pattern_size );
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

	if( ( (size64_t) signature->pattern_size > data_size )
	 || ( (size64_t) pattern_offset > ( data_size - signature->pattern_size ) ) )
	{
		/* If the pattern size exceeds the data size were are done scanning.
		 */
		return( 0 );
	}
	if( ( signature->pattern_size > buffer_size )
	 || ( (size64_t) scan_offset > ( buffer_size - signature->pattern_size ) ) )
	{
		if( pattern_offsets_mode != LIBSIGSCAN_PATTERN_OFFSET_MODE_UNBOUND )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid pattern size value out of bounds.",
			 function );

			return( -1 );
		}
		return( 0 );
	}
	if( memory_compare(
	     &( buffer[ scan_offset ] ),
	     signature->pattern,
	     signature->pattern_size ) != 0 )
	{
		return( 0 );
	}
	if( pattern_offsets_mode != LIBSIGSCAN_PATTERN_OFFSET_MODE_UNBOUND )
	{
		return( ( data_offset + scan_offset ) == pattern_offset );
	}
	return( 1 );
}

