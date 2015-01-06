/*
 * Scan handle
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
#include <file_stream.h>
#include <memory.h>
#include <types.h>

#include "scan_handle.h"
#include "sigscantools_libcerror.h"
#include "sigscantools_libcstring.h"
#include "sigscantools_libsigscan.h"

#define SCAN_HANDLE_NOTIFY_STREAM		stdout

/* Creates an info handle
 * Make sure the value scan_handle is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int scan_handle_initialize(
     scan_handle_t **scan_handle,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_initialize";

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid info handle.",
		 function );

		return( -1 );
	}
	if( *scan_handle != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid info handle value already set.",
		 function );

		return( -1 );
	}
	*scan_handle = memory_allocate_structure(
	                scan_handle_t );

	if( *scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create info handle.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *scan_handle,
	     0,
	     sizeof( scan_handle_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear info handle.",
		 function );

		goto on_error;
	}
	if( libsigscan_scanner_initialize(
	     &( ( *scan_handle )->scanner ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize scanner.",
		 function );

		goto on_error;
	}
	( *scan_handle )->notify_stream = SCAN_HANDLE_NOTIFY_STREAM;

	return( 1 );

on_error:
	if( *scan_handle != NULL )
	{
		memory_free(
		 *scan_handle );

		*scan_handle = NULL;
	}
	return( -1 );
}

/* Frees an info handle
 * Returns 1 if successful or -1 on error
 */
int scan_handle_free(
     scan_handle_t **scan_handle,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_free";
	int result            = 1;

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid info handle.",
		 function );

		return( -1 );
	}
	if( *scan_handle != NULL )
	{
		if( ( *scan_handle )->scanner != NULL )
		{
			if( libsigscan_scanner_free(
			     &( ( *scan_handle )->scanner ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free scanner.",
				 function );

				result = -1;
			}
		}
		memory_free(
		 *scan_handle );

		*scan_handle = NULL;
	}
	return( result );
}

/* Signals the info handle to abort
 * Returns 1 if successful or -1 on error
 */
int scan_handle_signal_abort(
     scan_handle_t *scan_handle,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_signal_abort";

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid info handle.",
		 function );

		return( -1 );
	}
	scan_handle->abort = 1;

	if( scan_handle->scanner != NULL )
	{
		if( libsigscan_scanner_signal_abort(
		     scan_handle->scanner,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to signal scanner to abort.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

/* Scans the input
 * Returns 1 if successful or -1 on error
 */
int scan_handle_scan_input(
     scan_handle_t *scan_handle,
     libsigscan_scan_state_t *scan_state,
     const libcstring_system_character_t *filename,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_scan_input";

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid info handle.",
		 function );

		return( -1 );
	}
#if defined( LIBCSTRING_HAVE_WIDE_SYSTEM_CHARACTER )
	if( libsigscan_scanner_scan_file_wide(
	     scan_handle->scanner,
	     scan_state,
	     filename,
	     error ) != 1 )
#else
	if( libsigscan_scanner_scan_file(
	     scan_handle->scanner,
	     scan_state,
	     filename,
	     error ) != 1 )
#endif
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to scan file.",
		 function );

		return( -1 );
	}
	if( scan_handle_scan_results_fprint(
	     scan_handle,
	     scan_state,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_PRINT_FAILED,
		 "%s: unable to print scan results.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Prints the scan results
 * Returns 1 if successful or -1 on error
 */
int scan_handle_scan_results_fprint(
     scan_handle_t *scan_handle,
     libsigscan_scan_state_t *scan_state,
     libcerror_error_t **error )
{
	libsigscan_scan_result_t *scan_result = NULL;
	static char *function                 = "scan_handle_scan_results_fprint";
	char *identifier                      = NULL;
	size_t identifier_size                = 0;
	int number_of_results                 = 0;
	int result_index                      = 0;

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid info handle.",
		 function );

		return( -1 );
	}
	if( libsigscan_scan_state_get_number_of_results(
	     scan_state,
	     &number_of_results,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of scan results.",
		 function );

		goto on_error;
	}
	fprintf(
	 scan_handle->notify_stream,
	 "Signature scanner:\n" );

	fprintf(
	 scan_handle->notify_stream,
	 "\tNumber of scan results\t: %d\n",
	 number_of_results );

	fprintf(
	 scan_handle->notify_stream,
	 "\n" );

	if( number_of_results > 0 )
	{
		for( result_index = 0;
		     result_index < number_of_results;
		     result_index++ )
		{
			fprintf(
			 scan_handle->notify_stream,
			 "Scan result: %d\n",
			 result_index );

			if( libsigscan_scan_state_get_result(
			     scan_state,
			     result_index,
			     &scan_result,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve scan result: %d.",
				 function,
				 result_index );

				goto on_error;
			}
			if( libsigscan_scan_result_get_identifier_size(
			     scan_result,
			     &identifier_size,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve scan result: %d identifier size.",
				 function,
				 result_index );

				goto on_error;
			}
			if( identifier_size == 0 )
			{
				fprintf(
				 scan_handle->notify_stream,
				 "\tIdentifier\t\t\t: %s\n",
				 identifier );
			}
			else
			{
				identifier = (char *) memory_allocate(
				                       sizeof( char ) * identifier_size );

				if( identifier == NULL )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_MEMORY,
					 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
					 "%s: unable to create info handle.",
					 function );

					 goto on_error;
				}
				if( libsigscan_scan_result_get_identifier(
				     scan_result,
				     identifier,
				     identifier_size,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
					 "%s: unable to retrieve scan result: %d identifier.",
					 function,
					 result_index );

					goto on_error;
				}
				fprintf(
				 scan_handle->notify_stream,
				 "\tIdentifier\t\t\t: %s\n",
				 identifier );

				memory_free(
				 identifier );

				identifier = NULL;
			}
			if( libsigscan_scan_result_free(
			     &scan_result,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free scan result.",
				 function );

				goto on_error;
			}
			fprintf(
			 scan_handle->notify_stream,
			 "\n" );
		}
	}
	return( 1 );

on_error:
	if( identifier != NULL )
	{
		memory_free(
		 identifier );
	}
	if( scan_result != NULL )
	{
		libsigscan_scan_result_free(
		 &scan_result,
		 NULL );
	}
	return( -1 );
}

