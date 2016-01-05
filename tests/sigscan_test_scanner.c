/*
 * Library scanner type testing program
 *
 * Copyright (C) 2014-2016, Joachim Metz <joachim.metz@gmail.com>
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

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include <stdio.h>

#include "sigscan_test_libcerror.h"
#include "sigscan_test_libcstring.h"
#include "sigscan_test_libsigscan.h"
#include "sigscan_test_unused.h"

/* Define to make qcow_test_seek generate verbose output
 */
#define SIGSCAN_TEST_SCANNER_VERBOSE

typedef struct sigscan_signature sigscan_signature_t;

struct sigscan_signature
{
	/* The identifier
	 */
	char *identifier;

	/* The pattern offset
	 */
	off64_t pattern_offset;

	/* The pattern
	 */
	uint8_t *pattern;

	/* The pattern size
	 */
	size_t pattern_size;

	/* The signature flags
	 */
	uint32_t signature_flags;
};

/* Tests initializing the scanner
 * Make sure the value scanner is referencing, is set to NULL
 * Returns 1 if successful, 0 if not or -1 on error
 */
int sigscan_test_scanner_initialize(
     libsigscan_scanner_t **scanner,
     int expected_result )
{
	libcerror_error_t *error = NULL;
	static char *function    = "sigscan_test_scanner_initialize";
	int result               = 0;

	fprintf(
	 stdout,
	 "Testing initialize\t" );

	result = libsigscan_scanner_initialize(
	          scanner,
	          &error );

	if( result == -1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create scanner.",
		 function );
	}
	if( result != expected_result )
	{
		fprintf(
		 stdout,
		 "(FAIL)" );
	}
	else
	{
		fprintf(
		 stdout,
		 "(PASS)" );
	}
	fprintf(
	 stdout,
	 "\n" );

	if( result == -1 )
	{
		libcerror_error_backtrace_fprint(
		 error,
		 stdout );

		libcerror_error_free(
		 &error );
	}
	if( result == 1 )
	{
		if( libsigscan_scanner_free(
		     scanner,
		     &error ) == -1 )
		{
			libcerror_error_set(
			 &error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free scanner.",
			 function );

			libcerror_error_backtrace_fprint(
			 error,
			 stdout );

			libcerror_error_free(
			 &error );

			return( -1 );
		}
	}
	if( result != expected_result )
	{
		return( 0 );
	}
	return( 1 );
}

/* Tests scanning a buffer of data
 * Returns 1 if successful, 0 if not or -1 on error
 */
int sigscan_test_scanner_scan_buffer(
     libsigscan_scanner_t *scanner,
     const uint8_t *buffer,
     size_t buffer_size,
     int expected_number_of_scan_results,
     libcerror_error_t **error )
{
	libsigscan_scan_state_t *scan_state = NULL;
	static char *function               = "sigscan_test_scanner_scan_buffer";
	int number_of_scan_results          = 0;
	int result                          = 0;

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
	if( libsigscan_scan_state_initialize(
	     &scan_state,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create scan state.",
		 function );

		goto on_error;
	}
	if( libsigscan_scan_state_set_data_size(
	     scan_state,
	     buffer_size,
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
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to start scan.",
		 function );

		goto on_error;
	}
	if( libsigscan_scanner_scan_buffer(
	     scanner,
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

		goto on_error;
	}
	if( libsigscan_scanner_scan_stop(
	     scanner,
	     scan_state,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to stop scan.",
		 function );

		goto on_error;
	}
	if( libsigscan_scan_state_get_number_of_results(
	     scan_state,
	     &number_of_scan_results,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to retrieve number of scan results.",
		 function );

		goto on_error;
	}
	result = ( number_of_scan_results == expected_number_of_scan_results );

/* TODO compare scan result signature and offsets */
	fprintf(
	 stdout,
	 "Testing scan\t" );

	if( result == 0 )
	{
		fprintf(
		 stdout,
		 "(FAIL)" );
	}
	else
	{
		fprintf(
		 stdout,
		 "(PASS)" );
	}
	fprintf(
	 stdout,
	 "\n" );

	if( libsigscan_scan_state_free(
	     &scan_state,
	     error ) == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free scan state.",
		 function );

		goto on_error;
	}
	return( result );

on_error:
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	return( -1 );
}

/* Tests scanning data
 * Returns 1 if successful, 0 if not or -1 on error
 */
int sigscan_test_scanner_scan(
     void )
{
	libcerror_error_t *error       = NULL;
	libsigscan_scanner_t *scanner  = NULL;
	sigscan_signature_t *signature = NULL;
	static char *function          = "sigscan_test_scanner_scan";
	size_t identifier_size         = 0;
	int expected_result            = 0;
	int result                     = 0;
	int signatures_index           = 0;

	uint8_t _7z_pattern[] = {
		'7', 'z', 0xbc, 0xaf, 0x27, 0x1c };

	uint8_t esedb_pattern[] = {
		0xef, 0xcd, 0xab, 0x89 };

	uint8_t evt_pattern[] = {
		0x30, 0x00, 0x00, 0x00, 'L', 'f', 'L', 'e', 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };

	uint8_t evtx_pattern[] = {
		'E', 'l', 'f', 'F', 'i', 'l', 'e', 0x00 };

	uint8_t ewf_e01_pattern[] = {
		'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00 };

	uint8_t ewf_l01_pattern[] = {
		'L', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00 };

	uint8_t lnk_pattern[] = {
		0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x46 };

	uint8_t msiecf_pattern[] = {
		'C', 'l', 'i', 'e', 'n', 't', ' ', 'U', 'r', 'l', 'C', 'a', 'c', 'h', 'e', ' ',
		'M', 'M', 'F', ' ', 'V', 'e', 'r', ' ' };

	uint8_t nk2_pattern[] = {
		0x0d, 0xf0, 0xad, 0xba, 0xa0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };

	uint8_t olecf_pattern[] = {
		0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 };

	uint8_t olecf_beta_pattern[] = {
		0x0e, 0x11, 0xfc, 0x0d, 0xd0, 0xcf, 0x11, 0x0e };

	uint8_t pff_pattern[] = {
		'!', 'B', 'D', 'N' };

	uint8_t qcow_pattern[] = {
		'Q', 'F', 'I', 0xfb };

	uint8_t rar_pattern[] = {
		'R', 'a', 'r', '!', 0x1a, 0x07, 0x00 };

	uint8_t regf_pattern[] = {
		'r', 'e', 'g', 'f' };

	uint8_t vhdi_pattern[] = {
		'c', 'o', 'n', 'e', 'c', 't', 'i', 'x' };

	uint8_t wtcdb_cache_pattern[] = {
		'C', 'M', 'M', 'M' };

	uint8_t wtcdb_index_pattern[] = {
		'I', 'M', 'M', 'M' };

	sigscan_signature_t signatures[] = {
		{ "7z",			0,	_7z_pattern,		6,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "esedb",		4,	esedb_pattern,		4,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "evt",		0,	evt_pattern,		16,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "evtx",		0,	evtx_pattern,		8,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "ewf_e01",		0,	ewf_e01_pattern,	8,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "ewf_l01",		0,	ewf_l01_pattern,	8,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "lnk",		0,	lnk_pattern,		20,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "msiecf",		0,	msiecf_pattern,		24,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "nk2",		0,	nk2_pattern,		12,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "olecf",		0,	olecf_pattern,		8,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "olecf_beta",		0,	olecf_beta_pattern,	8,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "pff",		0,	pff_pattern,		4,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "qcow",		0,	qcow_pattern,		4,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "rar",		0,	rar_pattern,		7,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "regf",		0,	regf_pattern,		4,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "vhdi_header",	0,	vhdi_pattern,		8,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "vhdi_footer",	512,	vhdi_pattern,		8,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_END },
		{ "wtcdb_cache",	0,	wtcdb_cache_pattern,	4,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ "wtcdb_index",	0,	wtcdb_index_pattern,	4,	LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START },
		{ NULL,			0,	NULL, 			0,	0 },
	};

	/* Random data
	 */
	uint8_t random_data[] = {
		0x01, 0xfa, 0xe0, 0xbe, 0x99, 0x8e, 0xdb, 0x70, 0xea, 0xcc, 0x6b, 0xae, 0x2f, 0xf5, 0xa2, 0xe4 };

	/* Boundary scan test data
	 */
	uint8_t boundary_data_part1[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'P', 'K' };
	uint8_t boundary_data_part2[] = {
		0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'Z' };

	if( libsigscan_scanner_initialize(
	     &scanner,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create scanner.",
		 function );

		goto on_error;
	}
	signature = &( signatures[ signatures_index++ ] );

	while( signature->identifier != NULL )
	{
		identifier_size = 1 + libcstring_narrow_string_length(
		                       signature->identifier );

		if( libsigscan_scanner_add_signature(
		     scanner,
		     signature->identifier,
		     identifier_size,
		     signature->pattern_offset,
		     signature->pattern,
		     signature->pattern_size,
		     signature->signature_flags,
		     &error ) != 1 )
		{
			libcerror_error_set(
			 &error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
			 "%s: unable to append signature: %s.",
			 function,
			 signature->identifier );

			goto on_error;
		}
		signature = &( signatures[ signatures_index++ ] );
	}
	if( sigscan_test_scanner_scan_buffer(
	     scanner,
	     lnk_pattern,
	     20,
	     1,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to scan buffer.",
		 function );

		goto on_error;
	}
	if( sigscan_test_scanner_scan_buffer(
	     scanner,
	     lnk_pattern,
	     20,
	     1,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to scan buffer.",
		 function );

		goto on_error;
	}
	if( sigscan_test_scanner_scan_buffer(
	     scanner,
	     regf_pattern,
	     4,
	     1,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to scan buffer.",
		 function );

		goto on_error;
	}
	if( sigscan_test_scanner_scan_buffer(
	     scanner,
	     random_data,
	     16,
	     0,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to scan buffer.",
		 function );

		goto on_error;
	}
/* TODO add more tests */
	if( libsigscan_scanner_free(
	     &scanner,
	     &error ) == -1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free scanner.",
		 function );

		goto on_error;
	}
	if( error != NULL )
	{
		if( result != 1 )
		{
			libsigscan_error_backtrace_fprint(
			 error,
			 stderr );
		}
		libsigscan_error_free(
		 &error );
	}
	if( result != expected_result )
	{
		return( 0 );
	}
	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_backtrace_fprint(
		 error,
		 stderr );

		libcerror_error_free(
		 &error );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	return( -1 );
}

/* The main program
 */
#if defined( LIBCSTRING_HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] SIGSCAN_TEST_ATTRIBUTE_UNUSED )
#else
int main( int argc, char * const argv[] SIGSCAN_TEST_ATTRIBUTE_UNUSED )
#endif
{
	libsigscan_scanner_t *scanner = NULL;

	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

	if( argc != 1 )
	{
		fprintf(
		 stderr,
		 "Unsupported number of arguments.\n" );

		return( EXIT_FAILURE );
	}
#if defined( HAVE_DEBUG_OUTPUT ) && defined( SIGSCAN_TEST_SCANNER_VERBOSE )
	libsigscan_notify_set_verbose(
	 1 );
	libsigscan_notify_set_stream(
	 stderr,
	 NULL );
#endif
	/* Initialization tests
	 */
	scanner = NULL;

	if( sigscan_test_scanner_initialize(
	     &scanner,
	     1 ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to test initialize.\n" );

		return( EXIT_FAILURE );
	}
	scanner = NULL;

	scanner = (libsigscan_scanner_t *) 0x12345678UL;

	if( sigscan_test_scanner_initialize(
	     &scanner,
	     -1 ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to test initialize.\n" );

		return( EXIT_FAILURE );
	}
	if( sigscan_test_scanner_initialize(
	     NULL,
	     -1 ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to test initialize.\n" );

		return( EXIT_FAILURE );
	}
	/* Scan tests
	 */
	if( sigscan_test_scanner_scan() != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to test scan.\n" );

		return( EXIT_FAILURE );
	}
	return( EXIT_SUCCESS );
}

