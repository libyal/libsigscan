/*
 * Scanner functions
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

#include "libsigscan_definitions.h"
#include "libsigscan_libbfio.h"
#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_scanner.h"
#include "libsigscan_signature.h"

/* Creates a scanner
 * Make sure the value scanner is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_initialize(
     libsigscan_scanner_t **scanner,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_initialize";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	if( *scanner != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scanner value already set.",
		 function );

		return( -1 );
	}
	internal_scanner = memory_allocate_structure(
	                    libsigscan_internal_scanner_t );

	if( internal_scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scanner.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_scanner,
	     0,
	     sizeof( libsigscan_internal_scanner_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear scanner.",
		 function );

		memory_free(
		 internal_scanner );

		return( -1 );
	}
	if( libcdata_array_initialize(
	     &( internal_scanner->signatures_array ),
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create signatures array.",
		 function );

		goto on_error;
	}
	*scanner = (libsigscan_scanner_t *) internal_scanner;

	return( 1 );

on_error:
	if( internal_scanner != NULL )
	{
		if( internal_scanner->signatures_array != NULL )
		{
			libcdata_array_free(
			 &( internal_scanner->signatures_array ),
			 NULL,
			 NULL );
		}
		memory_free(
		 internal_scanner );
	}
	return( -1 );
}

/* Frees a scanner
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_free(
     libsigscan_scanner_t **scanner,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_free";
	int result                                      = 1;

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	if( *scanner != NULL )
	{
		internal_scanner = (libsigscan_internal_scanner_t *) *scanner;
		*scanner         = NULL;

		if( libcdata_array_free(
		     &( internal_scanner->signatures_array ),
		     (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_signature_free,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free signatures array.",
			 function );

			result = -1;
		}
		memory_free(
		 internal_scanner );
	}
	return( result );
}

/* Signals the scanner to abort its current activity
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_signal_abort(
     libsigscan_scanner_t *scanner,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_signal_abort";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

	internal_scanner->abort = 1;

	return( 1 );
}

/* Adds a signature
 * Returns 1 if successful, 0 if signature already exists or -1 on error
 */
int libsigscan_scanner_add_signature(
     libsigscan_scanner_t *scanner,
     const char *identifier,
     size_t identifier_size,
     off64_t offset,
     const uint8_t *pattern,
     size_t pattern_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	libsigscan_signature_t *signature               = NULL;
	static char *function                           = "libsigscan_scanner_add_signature";
	int entry_index                                 = 0;

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

	if( internal_scanner->scan_tree_initialized != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scanner - scan tree already initialized.",
		 function );

		return( -1 );
	}
	if( pattern_size < 4 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid pattern value too small.",
		 function );

		return( -1 );
	}
	if( libsigscan_signature_initialize(
	     &signature,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create signature.",
		 function );

		goto on_error;
	}
	if( libcdata_array_append_entry(
	     internal_scanner->signatures_array,
	     &entry_index,
	     (intptr_t *) signature,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to append signature to signatures array.",
		 function );

		goto on_error;
	}
	signature = NULL;

	return( 1 );

on_error:
	if( signature != NULL )
	{
		libsigscan_signature_initialize(
		 &signature,
		 NULL );
	}
	return( -1 );
}

/* Starts the scan
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_start_scan(
     libsigscan_scanner_t *scanner,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_start_scan";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

/* TODO initialize scan trees */
	return( 1 );
}

/* Stops the scan
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_stop_scan(
     libsigscan_scanner_t *scanner,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_stop_scan";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

/* TODO */
	return( 1 );
}

/* Scans a buffer
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_buffer(
     libsigscan_scanner_t *scanner,
     const uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_scan_buffer";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

/* TODO */
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
		 "%s: invalid buffer size value out of bounds.",
		 function );

		return( -1 );
	}
/* TODO */
	return( 1 );
}

/* Scans a file
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_file(
     libsigscan_scanner_t *scanner,
     const char *filename,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_scan_file";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

/* TODO */
	return( 1 );
}

#if defined( HAVE_WIDE_CHARACTER_TYPE )

/* Scans a file
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_file_wide(
     libsigscan_scanner_t *scanner,
     const wchar_t *filename,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_scan_file_wide";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

/* TODO */
	return( 1 );
}

#endif /* defined( HAVE_WIDE_CHARACTER_TYPE ) */

/* Scans a file using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_file_io_handle(
     libsigscan_scanner_t *scanner,
     libbfio_handle_t *file_io_handle,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_scan_file_io_handle";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

/* TODO */
	return( 1 );
}

/* Retrieves the number of scan results
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_get_number_of_scan_results(
     libsigscan_scanner_t *scanner,
     int *number_of_scan_results,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_get_number_of_scan_results";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

/* TODO */
	return( 1 );
}

/* Retrieves a specific scan result
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_get_scan_result(
     libsigscan_scanner_t *scanner,
     int scan_result_index,
     libsigscan_scan_result_t **scan_result,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_get_scan_result";

	if( scanner == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	internal_scanner = (libsigscan_internal_scanner_t *) scanner;

/* TODO */
	return( 1 );
}

