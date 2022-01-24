/*
 * Scan result functions
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

#include "libsigscan_libcerror.h"
#include "libsigscan_scan_result.h"
#include "libsigscan_types.h"

/* Creates a scan result
 * Make sure the value scan_result is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_result_initialize(
     libsigscan_scan_result_t **scan_result,
     off64_t offset,
     libsigscan_signature_t *signature,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_result_t *internal_scan_result = NULL;
	static char *function                                   = "libsigscan_scan_result_initialize";

	if( scan_result == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan result.",
		 function );

		return( -1 );
	}
	if( *scan_result != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan result value already set.",
		 function );

		return( -1 );
	}
	if( offset < 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_ZERO_OR_LESS,
		 "%s: invalid offset value zero or less.",
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
	internal_scan_result = memory_allocate_structure(
	                        libsigscan_internal_scan_result_t );

	if( internal_scan_result == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan result.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_scan_result,
	     0,
	     sizeof( libsigscan_internal_scan_result_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear scan result.",
		 function );

		memory_free(
		 internal_scan_result );

		return( -1 );
	}
	internal_scan_result->offset    = offset;
	internal_scan_result->signature = signature;

	*scan_result = (libsigscan_scan_result_t *) internal_scan_result;

	return( 1 );

on_error:
	if( internal_scan_result != NULL )
	{
		memory_free(
		 internal_scan_result );
	}
	return( -1 );
}

/* Frees a scan result
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_result_free(
     libsigscan_scan_result_t **scan_result,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_result_free";

	if( scan_result == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan result.",
		 function );

		return( -1 );
	}
	if( *scan_result != NULL )
	{
		*scan_result = NULL;
	}
	return( 1 );
}

/* Frees a scan result
 * Returns 1 if successful or -1 on error
 */
int libsigscan_internal_scan_result_free(
     libsigscan_internal_scan_result_t **internal_scan_result,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_internal_scan_result_free";

	if( internal_scan_result == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan result.",
		 function );

		return( -1 );
	}
	if( *internal_scan_result != NULL )
	{
		/* The signature is a reference and freed elsewhere
		 */
		memory_free(
		 *internal_scan_result );

		*internal_scan_result = NULL;
	}
	return( 1 );
}

/* Retrieves the size of the identifier
 * The returned size includes the end of string character
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_result_get_identifier_size(
     libsigscan_scan_result_t *scan_result,
     size_t *identifier_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_result_t *internal_scan_result = NULL;
	static char *function                                   = "libsigscan_scan_result_get_identifier_size";

	if( scan_result == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan result.",
		 function );

		return( -1 );
	}
	internal_scan_result = (libsigscan_internal_scan_result_t *) scan_result;

	if( libsigscan_signature_get_identifier_size(
	     internal_scan_result->signature,
	     identifier_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve identifier size.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves the identifier
 * The size should include the end of string character
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_result_get_identifier(
     libsigscan_scan_result_t *scan_result,
     char *identifier,
     size_t identifier_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_result_t *internal_scan_result = NULL;
	static char *function                                   = "libsigscan_scan_result_get_identifier";

	if( scan_result == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan result.",
		 function );

		return( -1 );
	}
	internal_scan_result = (libsigscan_internal_scan_result_t *) scan_result;

	if( libsigscan_signature_get_identifier(
	     internal_scan_result->signature,
	     identifier,
	     identifier_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve identifier.",
		 function );

		return( -1 );
	}
	return( 1 );
}

