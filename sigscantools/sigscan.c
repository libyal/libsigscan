/*
 * Scans a file for binary signatures
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
#include <file_stream.h>
#include <memory.h>
#include <system_string.h>
#include <types.h>

#if defined( HAVE_UNISTD_H )
#include <unistd.h>
#endif

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "scan_handle.h"
#include "sigscantools_getopt.h"
#include "sigscantools_libcerror.h"
#include "sigscantools_libclocale.h"
#include "sigscantools_libcnotify.h"
#include "sigscantools_libsigscan.h"
#include "sigscantools_output.h"
#include "sigscantools_signal.h"
#include "sigscantools_unused.h"

scan_handle_t *sigscan_scan_handle = NULL;
int sigscan_abort                  = 0;

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use sigscan to scan a file for binary signatures.\n\n" );

	fprintf( stream, "Usage: sigscan [ -c configuration_file ] [ -hvV ] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-c:     specify the configuration file, defaults\n"
	                 "\t        to: sigscan.conf\n" );
	fprintf( stream, "\t-h:     shows this help\n" );
	fprintf( stream, "\t-v:     verbose output to stderr\n" );
	fprintf( stream, "\t-V:     print version\n" );
}

/* Signal handler for sigscan
 */
void sigscan_signal_handler(
      sigscantools_signal_t signal SIGSCANTOOLS_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error = NULL;
	static char *function    = "sigscan_signal_handler";

	SIGSCANTOOLS_UNREFERENCED_PARAMETER( signal )

	sigscan_abort = 1;

	if( sigscan_scan_handle != NULL )
	{
		if( scan_handle_signal_abort(
		     sigscan_scan_handle,
		     &error ) != 1 )
		{
			libcnotify_printf(
			 "%s: unable to signal info handle to abort.\n",
			 function );

			libcnotify_print_error_backtrace(
			 error );
			libcerror_error_free(
			 &error );
		}
	}
	/* Force stdin to close otherwise any function reading it will remain blocked
	 */
#if defined( WINAPI ) && !defined( __CYGWIN__ )
	if( _close(
	     0 ) != 0 )
#else
	if( close(
	     0 ) != 0 )
#endif
	{
		libcnotify_printf(
		 "%s: unable to close stdin.\n",
		 function );
	}
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] )
#else
int main( int argc, char * const argv[] )
#endif
{
	libcerror_error_t *error                      = NULL;
	system_character_t *option_configuration_file = _SYSTEM_STRING( "sigscan.conf" );
	system_character_t *source                    = NULL;
	libsigscan_scan_state_t *scan_state           = NULL;
	char *program                                 = "sigscan";
	system_integer_t option                       = 0;
	int verbose                                   = 0;

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 1 );

	if( libclocale_initialize(
	     "sigscantools",
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize locale values.\n" );

		goto on_error;
	}
	if( sigscantools_output_initialize(
	     _IONBF,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize output settings.\n" );

		goto on_error;
	}
	sigscanoutput_version_fprint(
	 stdout,
	 program );

	while( ( option = sigscantools_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "c:hvV" ) ) ) != (system_integer_t) -1 )
	{
		switch( option )
		{
			case (system_integer_t) '?':
			default:
				fprintf(
				 stderr,
				 "Invalid argument: %" PRIs_SYSTEM "\n",
				 argv[ optind - 1 ] );

				usage_fprint(
				 stdout );

				return( EXIT_FAILURE );

			case (system_integer_t) 'c':
				option_configuration_file = optarg;

				break;

			case (system_integer_t) 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case (system_integer_t) 'v':
				verbose = 1;

				break;

			case (system_integer_t) 'V':
				sigscanoutput_copyright_fprint(
				 stdout );

				return( EXIT_SUCCESS );
		}
	}
	if( optind == argc )
	{
		fprintf(
		 stderr,
		 "Missing source file.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	source = argv[ optind ];

	libcnotify_verbose_set(
	 verbose );
	libsigscan_notify_set_stream(
	 stderr,
	 NULL );
	libsigscan_notify_set_verbose(
	 verbose );

/* TODO check if option_configuration_file exists */

	if( scan_handle_initialize(
	     &sigscan_scan_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create scan handle.\n" );

		goto on_error;
	}
	if( libsigscan_scan_state_initialize(
	     &scan_state,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create scan state.\n" );

		goto on_error;
	}
	if( scan_handle_read_signature_definitions(
	     sigscan_scan_handle,
	     option_configuration_file,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to read signatures from: %" PRIs_SYSTEM ".\n",
		 option_configuration_file );

		goto on_error;
	}
	if( scan_handle_scan_input(
	     sigscan_scan_handle,
	     scan_state,
	     source,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to scan: %" PRIs_SYSTEM ".\n",
		 source );

		goto on_error;
	}
	if( libsigscan_scan_state_free(
	     &scan_state,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free scan state.\n" );

		goto on_error;
	}
	if( scan_handle_free(
	     &sigscan_scan_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free info handle.\n" );

		goto on_error;
	}
	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	if( sigscan_scan_handle != NULL )
	{
		scan_handle_free(
		 &sigscan_scan_handle,
		 NULL );
	}
	return( EXIT_FAILURE );
}

