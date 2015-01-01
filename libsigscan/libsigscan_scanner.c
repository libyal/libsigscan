/*
 * Scanner functions
 *
 * Copyright (C) 2014-2015, Joachim Metz <joachim.metz@gmail.com>
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
#include "libsigscan_scan_state.h"
#include "libsigscan_scan_tree.h"
#include "libsigscan_signature.h"
#include "libsigscan_types.h"

/* Creates a scanner
 * Make sure the value scanner is referencing, is set to NULL
 *
 * Currently only supports "bounded" sigatures (signatures with a fixed offset).
 * Unbounded signatures can be set but will be ignored.
 *
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
	if( libcdata_list_initialize(
	     &( internal_scanner->signatures_list ),
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
	*scanner = (libsigscan_scanner_t *) internal_scanner;

	return( 1 );

on_error:
	if( internal_scanner != NULL )
	{
		if( internal_scanner->signatures_list != NULL )
		{
			libcdata_list_free(
			 &( internal_scanner->signatures_list ),
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

		if( internal_scanner->header_scan_tree != NULL )
		{
			if( libsigscan_scan_tree_free(
			     &( internal_scanner->header_scan_tree ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free header scan tree.",
				 function );

				result = -1;
			}
		}
		if( internal_scanner->footer_scan_tree != NULL )
		{
			if( libsigscan_scan_tree_free(
			     &( internal_scanner->footer_scan_tree ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free footer scan tree.",
				 function );

				result = -1;
			}
		}
		if( libcdata_list_free(
		     &( internal_scanner->signatures_list ),
		     (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_signature_free,
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
     off64_t pattern_offset,
     const uint8_t *pattern,
     size_t pattern_size,
     uint32_t signature_flags,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	libsigscan_signature_t *signature               = NULL;
	static char *function                           = "libsigscan_scanner_add_signature";

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

	if( internal_scanner->header_scan_tree != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scanner - header scan tree already set.",
		 function );

		return( -1 );
	}
	if( internal_scanner->footer_scan_tree != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scanner - footer scan tree already set.",
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
	if( libsigscan_signature_set(
	     signature,
	     identifier,
	     identifier_size,
	     pattern_offset,
	     pattern,
	     pattern_size,
	     signature_flags,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set signature values.",
		 function );

		goto on_error;
	}
	if( libcdata_list_append_value(
	     internal_scanner->signatures_list,
	     (intptr_t *) signature,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to append signature to signatures list.",
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
int libsigscan_scanner_scan_start(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_scan_start";
	int result                                      = 0;

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

	if( internal_scanner->header_scan_tree == NULL )
	{
		if( libsigscan_scan_tree_initialize(
		     &( internal_scanner->header_scan_tree ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create header scan tree.",
			 function );

			return( -1 );
		}
		result = libsigscan_scan_tree_build(
		          internal_scanner->header_scan_tree,
		          internal_scanner->signatures_list,
		          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to build header scan tree.",
			 function );

			libsigscan_scan_tree_free(
			 &( internal_scanner->header_scan_tree ),
			 NULL );

			return( -1 );
		}
	}
	if( internal_scanner->footer_scan_tree == NULL )
	{
		if( libsigscan_scan_tree_initialize(
		     &( internal_scanner->footer_scan_tree ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create footer scan tree.",
			 function );

			return( -1 );
		}
		result = libsigscan_scan_tree_build(
		          internal_scanner->footer_scan_tree,
		          internal_scanner->signatures_list,
		          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_END,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to build footer scan tree.",
			 function );

			libsigscan_scan_tree_free(
			 &( internal_scanner->footer_scan_tree ),
			 NULL );

			return( -1 );
		}
	}
/* TODO determine header spanning range */
/* TODO determine footer spanning range */
	if( libsigscan_scan_state_start(
	     scan_state,
	     internal_scanner->header_scan_tree->root_node,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set scan state.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Stops the scan
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_stop(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_scan_stop";

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

/* TODO check scan state - is the right state */
/* TODO scan remaining data */
	if( libsigscan_scan_state_stop(
	     scan_state,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set scan state.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Scans a buffer
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_buffer(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
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
/* TODO check scan state - is the right state */
/* TODO */
	return( 1 );
}

/* Scans a file
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_file(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
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

/* TODO check scan state - is the right state */
/* TODO set active node */
	if( libsigscan_scan_state_update(
	     scan_state,
	     NULL,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set scan state.",
		 function );

		return( -1 );
	}
	return( 1 );
}

#if defined( HAVE_WIDE_CHARACTER_TYPE )

/* Scans a file
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_file_wide(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
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

/* TODO check scan state - is the right state */
/* TODO set active node */
	if( libsigscan_scan_state_update(
	     scan_state,
	     NULL,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set scan state.",
		 function );

		return( -1 );
	}
	return( 1 );
}

#endif /* defined( HAVE_WIDE_CHARACTER_TYPE ) */

/* Scans a file using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_scan_file_io_handle(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
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

/* TODO check scan state - is the right state */
/* TODO set active node */
	if( libsigscan_scan_state_update(
	     scan_state,
	     NULL,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set scan state.",
		 function );

		return( -1 );
	}
	return( 1 );
}

