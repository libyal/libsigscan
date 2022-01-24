/*
 * Scanner functions
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
#include <narrow_string.h>
#include <types.h>
#include <wide_string.h>

#include "libsigscan_definitions.h"
#include "libsigscan_libbfio.h"
#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_libcnotify.h"
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
	internal_scanner->buffer_size = LIBSIGSCAN_DEFAULT_SCAN_BUFFER_SIZE;

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
		if( internal_scanner->scan_tree != NULL )
		{
			if( libsigscan_scan_tree_free(
			     &( internal_scanner->scan_tree ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free scan tree.",
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

/* Sets the scan buffer size
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scanner_set_scan_buffer_size(
     libsigscan_scanner_t *scanner,
     size_t scan_buffer_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scanner_t *internal_scanner = NULL;
	static char *function                           = "libsigscan_scanner_set_scan_buffer_size";

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

	if( ( scan_buffer_size == 0 )
	 || ( scan_buffer_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid scan buffer size value out of bounds.",
		 function );

		return( -1 );
	}
	internal_scanner->buffer_size = scan_buffer_size;

	return( 1 );
}

/* Adds a signature
 * Returns 1 if successful, 0 if signature already exists or -1 on error
 */
int libsigscan_scanner_add_signature(
     libsigscan_scanner_t *scanner,
     const char *identifier,
     size_t identifier_length,
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
	if( internal_scanner->scan_tree != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scanner - scan tree already set.",
		 function );

		return( -1 );
	}
	/* For now unbound signatures should not be be smaller than 4 bytes
	 * otherwise the skip value has little to no effect
	 */
	if( ( ( signature_flags & LIBSIGSCAN_SIGNATURE_FLAGS_MASK ) == LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET )
	 && ( pattern_size < 4 ) )
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
	     identifier_length,
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
#ifdef TODO_UNBOUND_SUPPORT
	if( internal_scanner->scan_tree == NULL )
	{
		if( libsigscan_scan_tree_initialize(
		     &( internal_scanner->scan_tree ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create scan tree.",
			 function );

			return( -1 );
		}
		result = libsigscan_scan_tree_build(
		          internal_scanner->scan_tree,
		          internal_scanner->signatures_list,
		          LIBSIGSCAN_PATTERN_OFFSET_MODE_UNBOUND,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to build scan tree.",
			 function );

			libsigscan_scan_tree_free(
			 &( internal_scanner->scan_tree ),
			 NULL );

			return( -1 );
		}
	}
#endif /* TODO_UNBOUND_SUPPORT */

	if( libsigscan_scan_state_start(
	     scan_state,
	     internal_scanner->header_scan_tree,
	     internal_scanner->footer_scan_tree,
	     internal_scanner->scan_tree,
	     internal_scanner->buffer_size,
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
	static char *function = "libsigscan_scanner_scan_stop";

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
	static char *function = "libsigscan_scanner_scan_buffer";

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
	if( libsigscan_scan_state_scan_buffer(
	     scan_state,
	     buffer,
	     buffer_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to scan buffer.",
		 function );

		return( -1 );
	}
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
	libbfio_handle_t *file_io_handle = NULL;
	static char *function            = "libsigscan_scanner_scan_file";
	size_t filename_length           = 0;

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
	if( filename == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid filename.",
		 function );

		return( -1 );
	}
	if( libbfio_file_initialize(
	     &file_io_handle,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create file IO handle.",
		 function );

		goto on_error;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libbfio_handle_set_track_offsets_read(
	     file_io_handle,
	     1,
	     error ) != 1 )
	{
                libcerror_error_set(
                 error,
                 LIBCERROR_ERROR_DOMAIN_RUNTIME,
                 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
                 "%s: unable to set track offsets read in file IO handle.",
                 function );

		goto on_error;
	}
#endif
	filename_length = narrow_string_length(
	                   filename );

	if( libbfio_file_set_name(
	     file_io_handle,
	     filename,
	     filename_length + 1,
	     error ) != 1 )
	{
                libcerror_error_set(
                 error,
                 LIBCERROR_ERROR_DOMAIN_RUNTIME,
                 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
                 "%s: unable to set filename in file IO handle.",
                 function );

		goto on_error;
	}
	if( libsigscan_scanner_scan_file_io_handle(
	     scanner,
	     scan_state,
	     file_io_handle,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to open file: %s.",
		 function,
		 filename );

		goto on_error;
	}
	if( libbfio_handle_free(
	     &file_io_handle,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free file IO handle.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( file_io_handle != NULL )
	{
		libbfio_handle_free(
		 &file_io_handle,
		 NULL );
	}
	return( -1 );
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
	libbfio_handle_t *file_io_handle = NULL;
	static char *function            = "libsigscan_scanner_scan_file_wide";
	size_t filename_length           = 0;

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
	if( filename == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid filename.",
		 function );

		return( -1 );
	}
	if( libbfio_file_initialize(
	     &file_io_handle,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create file IO handle.",
		 function );

		goto on_error;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libbfio_handle_set_track_offsets_read(
	     file_io_handle,
	     1,
	     error ) != 1 )
	{
                libcerror_error_set(
                 error,
                 LIBCERROR_ERROR_DOMAIN_RUNTIME,
                 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
                 "%s: unable to set track offsets read in file IO handle.",
                 function );

		goto on_error;
	}
#endif
	filename_length = wide_string_length(
	                   filename );

	if( libbfio_file_set_name_wide(
	     file_io_handle,
	     filename,
	     filename_length + 1,
	     error ) != 1 )
	{
                libcerror_error_set(
                 error,
                 LIBCERROR_ERROR_DOMAIN_RUNTIME,
                 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
                 "%s: unable to set filename in file IO handle.",
                 function );

		goto on_error;
	}
	if( libsigscan_scanner_scan_file_io_handle(
	     scanner,
	     scan_state,
	     file_io_handle,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to open file: %ls.",
		 function,
		 filename );

		goto on_error;
	}
	if( libbfio_handle_free(
	     &file_io_handle,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free file IO handle.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( file_io_handle != NULL )
	{
		libbfio_handle_free(
		 &file_io_handle,
		 NULL );
	}
	return( -1 );
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
	uint8_t *buffer                                 = NULL;
	static char *function                           = "libsigscan_scanner_scan_file_io_handle";
	size64_t file_size                              = 0;
	uint64_t footer_range_end                       = 0;
	uint64_t footer_range_size                      = 0;
	uint64_t footer_range_start                     = 0;
	uint64_t header_range_end                       = 0;
	uint64_t header_range_size                      = 0;
	uint64_t header_range_start                     = 0;
	size_t buffer_size                              = 0;
	size_t read_size                                = 0;
	ssize_t read_count                              = 0;
	int file_io_handle_is_open                      = 0;
	int has_footer_range                            = 0;
	int has_header_range                            = 0;
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

	file_io_handle_is_open = libbfio_handle_is_open(
	                          file_io_handle,
	                          error );

	if( file_io_handle_is_open == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to determine if file IO handle is open.",
		 function );

		goto on_error;
	}
	else if( file_io_handle_is_open == 0 )
	{
		if( libbfio_handle_open(
		     file_io_handle,
		     LIBBFIO_ACCESS_FLAG_READ,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_OPEN_FAILED,
			 "%s: unable to open file IO handle.",
			 function );

			goto on_error;
		}
	}
	if( libbfio_handle_get_size(
	     file_io_handle,
	     &file_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve file size.",
		 function );

		goto on_error;
	}
	if( libsigscan_scan_state_set_data_size(
	     scan_state,
	     file_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set data size.",
		 function );

		goto on_error;
	}
	if( libsigscan_scanner_scan_start(
	     scanner,
	     scan_state,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set scan state.",
		 function );

		goto on_error;
	}
	if( internal_scanner->header_scan_tree == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid sacnner - missing header scan tree.",
		 function );

		goto on_error;
	}
	if( internal_scanner->footer_scan_tree == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid sacnner - missing footer scan tree.",
		 function );

		goto on_error;
	}
	if( libsigscan_scan_state_get_buffer_size(
	     scan_state,
	     &buffer_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to retrieve scan buffer size.",
		 function );

		goto on_error;
	}
	if( ( buffer_size == 0 )
	 || ( buffer_size > MEMORY_MAXIMUM_ALLOCATION_SIZE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid buffer size value out of bounds.",
		 function );

		goto on_error;
	}
	buffer = (uint8_t *) memory_allocate(
	                      sizeof( uint8_t ) * buffer_size );

	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan buffer.",
		 function );

		goto on_error;
	}
	result = libsigscan_scan_state_get_header_range(
	          scan_state,
	          &header_range_start,
	          &header_range_end,
	          &header_range_size,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve header range.",
		 function );

		goto on_error;
	}
	has_header_range = result;

	result = libsigscan_scan_state_get_footer_range(
	          scan_state,
	          &footer_range_start,
	          &footer_range_end,
	          &footer_range_size,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve footer range.",
		 function );

		goto on_error;
	}
	has_footer_range = result;

	if( has_footer_range != 0 )
	{
		if( footer_range_start < header_range_start )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid footer range value out of bounds.",
			 function );

			goto on_error;
		}
		if( ( footer_range_start >= header_range_start )
		 && ( footer_range_start <= header_range_end ) )
		{
			/* The footer range is encapsulated in the header range
			 */
			if( footer_range_end <= header_range_end )
			{
				has_footer_range = 0;
			}
			/* The footer range overlaps the header range at the end
			 */
			else if( footer_range_end > header_range_end )
			{
				header_range_end = footer_range_end;
				has_footer_range = 0;
			}
		}
	}
	if( has_header_range != 0 )
	{
		if( header_range_end > file_size )
		{
			header_range_size -= (size64_t) header_range_end - file_size;
			header_range_end   = (off64_t) file_size;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: scanning range: %" PRIu64 " - %" PRIu64 " for signatures.\n",
			 function,
			 header_range_start,
			 header_range_end );
		}
#endif
		if( header_range_size > 0 )
		{
			if( libbfio_handle_seek_offset(
			     file_io_handle,
			     (off64_t) header_range_start,
			     SEEK_SET,
			     error ) == -1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_SEEK_FAILED,
				 "%s: unable to seek file header offset: 0x%08" PRIx64 ".",
				 function,
				 header_range_start );

				goto on_error;
			}
			while( header_range_size > 0 )
			{
				if( header_range_size > buffer_size )
				{
					read_size = buffer_size;
				}
				else
				{
					read_size = (size_t) header_range_size;
				}
				read_count = libbfio_handle_read_buffer(
					      file_io_handle,
					      buffer,
					      read_size,
					      error );

				if( read_count != (ssize_t) read_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_IO,
					 LIBCERROR_IO_ERROR_READ_FAILED,
					 "%s: unable to read buffer.",
					 function );

					goto on_error;
				}
				if( libsigscan_scan_state_scan_buffer(
				     scan_state,
				     buffer,
				     read_size,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GENERIC,
					 "%s: unable to scan buffer.",
					 function );

					goto on_error;
				}
				header_range_size -= read_size;
			}
		}
	}
/* TODO scan unbound */
	if( has_footer_range != 0 )
	{
		if( footer_range_end > file_size )
		{
			footer_range_size -= (size64_t) footer_range_end - file_size;
			footer_range_end   = (off64_t) file_size;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: scanning range: %" PRIu64 " - %" PRIu64 " for signatures.\n",
			 function,
			 footer_range_start,
			 footer_range_end );
		}
#endif
		if( footer_range_size > 0 )
		{
			if( libbfio_handle_seek_offset(
			     file_io_handle,
			     (off64_t) footer_range_start,
			     SEEK_SET,
			     error ) == -1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_SEEK_FAILED,
				 "%s: unable to seek file header offset: 0x%08" PRIx64 ".",
				 function,
				 footer_range_start );

				goto on_error;
			}
/* TODO handle unbound */
			if( libsigscan_scan_state_flush(
			     scan_state,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GENERIC,
				 "%s: unable to flush scan state.",
				 function );

				goto on_error;
			}
			if( libsigscan_scan_state_set_data_offset(
			     scan_state,
			     (off64_t) footer_range_start,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
				 "%s: unable to set data offset.",
				 function );

				goto on_error;
			}
/* TODO handle unbound */
			while( footer_range_size > 0 )
			{
				if( footer_range_size > buffer_size )
				{
					read_size = buffer_size;
				}
				else
				{
					read_size = (size_t) footer_range_size;
				}
				read_count = libbfio_handle_read_buffer(
					      file_io_handle,
					      buffer,
					      read_size,
					      error );

				if( read_count != (ssize_t) read_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_IO,
					 LIBCERROR_IO_ERROR_READ_FAILED,
					 "%s: unable to read buffer.",
					 function );

					goto on_error;
				}
				if( libsigscan_scan_state_scan_buffer(
				     scan_state,
				     buffer,
				     read_size,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GENERIC,
					 "%s: unable to scan buffer.",
					 function );

					goto on_error;
				}
				footer_range_size -= read_size;
			}
		}
	}
	if( libsigscan_scanner_scan_stop(
	     scanner,
	     scan_state,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set scan state.",
		 function );

		goto on_error;
	}
	memory_free(
	 buffer );

	buffer = NULL;

	if( file_io_handle_is_open == 0 )
	{
		if( libbfio_handle_close(
		     file_io_handle,
		     error ) != 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_CLOSE_FAILED,
			 "%s: unable to close file IO handle.",
			 function );

			goto on_error;
		}
	}
	return( 1 );

on_error:
/* TODO set scan state to error ? */
	if( buffer != NULL )
	{
		memory_free(
		 buffer );
	}
	if( file_io_handle_is_open == 0 )
	{
		libbfio_handle_close(
		 file_io_handle,
		 NULL );
	}
	return( -1 );
}

