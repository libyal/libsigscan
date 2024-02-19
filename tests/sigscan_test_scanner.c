/*
 * Library scanner type test program
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
#include <file_stream.h>
#include <memory.h>
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>
#include <wide_string.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "sigscan_test_functions.h"
#include "sigscan_test_getopt.h"
#include "sigscan_test_libbfio.h"
#include "sigscan_test_libcerror.h"
#include "sigscan_test_libsigscan.h"
#include "sigscan_test_macros.h"
#include "sigscan_test_memory.h"

#include "../libsigscan/libsigscan_scan_state.h"
#include "../libsigscan/libsigscan_scanner.h"

#if !defined( LIBSIGSCAN_HAVE_BFIO )

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file_io_handle(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libbfio_handle_t *file_io_handle,
     libcerror_error_t **error );

#endif /* !defined( LIBSIGSCAN_HAVE_BFIO ) */

#if defined( HAVE_WIDE_SYSTEM_CHARACTER ) && SIZEOF_WCHAR_T != 2 && SIZEOF_WCHAR_T != 4
#error Unsupported size of wchar_t
#endif

/* Define to make sigscan_test_scanner generate verbose output
 */
#define SIGSCAN_TEST_SCANNER_VERBOSE

uint8_t sigscan_test_scanner_data1[ 128 ] = {
	0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x55, 0x72, 0x6c, 0x43, 0x61, 0x63, 0x68, 0x65, 0x20,
	0x4d, 0x4d, 0x46, 0x20, 0x56, 0x65, 0x72, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t sigscan_test_scanner_data2[ 128 ] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t sigscan_test_scanner_data3[ 128 ] = {
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x65,
	0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x75, 0x6e, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x65, 0x64, 0x20, 0x70, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x20, 0x20, 0x20, 0x0a, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };

/* Tests the libsigscan_scanner_initialize function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_initialize(
     void )
{
	libcerror_error_t *error        = NULL;
	libsigscan_scanner_t *scanner   = NULL;
	int result                      = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests = 1;
	int number_of_memset_fail_tests = 1;
	int test_number                 = 0;
#endif

	/* Test regular cases
	 */
	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_initialize(
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	scanner = (libsigscan_scanner_t *) 0x12345678UL;

	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	scanner = NULL;

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

#if defined( HAVE_SIGSCAN_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libsigscan_scanner_initialize with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_scanner_initialize(
		          &scanner,
		          &error );

		if( sigscan_test_malloc_attempts_before_fail != -1 )
		{
			sigscan_test_malloc_attempts_before_fail = -1;

			if( scanner != NULL )
			{
				libsigscan_scanner_free(
				 &scanner,
				 NULL );
			}
		}
		else
		{
			SIGSCAN_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			SIGSCAN_TEST_ASSERT_IS_NULL(
			 "scanner",
			 scanner );

			SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test libsigscan_scanner_initialize with memset failing
		 */
		sigscan_test_memset_attempts_before_fail = test_number;

		result = libsigscan_scanner_initialize(
		          &scanner,
		          &error );

		if( sigscan_test_memset_attempts_before_fail != -1 )
		{
			sigscan_test_memset_attempts_before_fail = -1;

			if( scanner != NULL )
			{
				libsigscan_scanner_free(
				 &scanner,
				 NULL );
			}
		}
		else
		{
			SIGSCAN_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			SIGSCAN_TEST_ASSERT_IS_NULL(
			 "scanner",
			 scanner );

			SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( HAVE_SIGSCAN_TEST_MEMORY ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scanner_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_scanner_free(
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libsigscan_scanner_signal_abort function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_signal_abort(
     libsigscan_scanner_t *scanner )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_scanner_signal_abort(
	          scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_signal_abort(
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libsigscan_scanner_set_scan_buffer_size function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_set_scan_buffer_size(
     libsigscan_scanner_t *scanner )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_scanner_set_scan_buffer_size(
	          scanner,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_set_scan_buffer_size(
	          NULL,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_set_scan_buffer_size(
	          scanner,
	          0,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_set_scan_buffer_size(
	          scanner,
	          (size_t) SIZE_MAX + 1,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libsigscan_scanner_add_signature function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_add_signature(
     libsigscan_scanner_t *scanner )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_scanner_add_signature(
	          scanner,
	          "test1",
	          6,
	          0,
	          (uint8_t *) "pattern",
	          7,
	          LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_add_signature(
	          NULL,
	          "test1",
	          6,
	          0,
	          (uint8_t *) "pattern",
	          7,
	          LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          NULL,
	          5,
	          0,
	          (uint8_t *) "pattern",
	          7,
	          LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "test1",
	          6,
	          0,
	          NULL,
	          7,
	          LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libsigscan_scanner_scan_start function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_scan_start(
     libsigscan_scanner_t *scanner )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	int result                          = 0;

	/* Initialize test
	 */
	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scanner_scan_start(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_scan_start(
	          NULL,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_start(
	          scanner,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scanner_scan_stop function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_scan_stop(
     libsigscan_scanner_t *scanner )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	int result                          = 0;

	/* Initialize test
	 */
	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_start(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scanner_scan_stop(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_scan_stop(
	          NULL,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_stop(
	          scanner,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scanner_scan_buffer function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_scan_buffer(
     libsigscan_scanner_t *scanner )
{
	uint8_t buffer[ 128 ];

	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	void *memset_result                 = NULL;
	int result                          = 0;

	/* Initialize test
	 */
	memset_result = memory_set(
	                 buffer,
	                 0,
	                 sizeof( uint8_t ) * 128 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_set_data_size(
	          scan_state,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_start(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scanner_scan_buffer(
	          scanner,
	          scan_state,
	          buffer,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_scan_buffer(
	          NULL,
	          scan_state,
	          buffer,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_buffer(
	          scanner,
	          NULL,
	          buffer,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_buffer(
	          scanner,
	          scan_state,
	          NULL,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = libsigscan_scanner_scan_stop(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scanner_scan_file function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_scan_file(
     const system_character_t *source )
{
	char narrow_source[ 256 ];

	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	libsigscan_scanner_t *scanner       = NULL;
	int result                          = 0;

	/* Initialize test
	 */
	result = sigscan_test_get_narrow_source(
	          source,
	          narrow_source,
	          256,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scanner_scan_file(
	          scanner,
	          scan_state,
	          narrow_source,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_scan_file(
	          NULL,
	          scan_state,
	          narrow_source,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_file(
	          scanner,
	          NULL,
	          narrow_source,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_file(
	          scanner,
	          scan_state,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	return( 0 );
}

#if defined( HAVE_WIDE_CHARACTER_TYPE )

/* Tests the libsigscan_scanner_scan_file_wide function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_scan_file_wide(
     const system_character_t *source )
{
	wchar_t wide_source[ 256 ];

	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	libsigscan_scanner_t *scanner       = NULL;
	int result                          = 0;

	/* Initialize test
	 */
	result = sigscan_test_get_wide_source(
	          source,
	          wide_source,
	          256,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scanner_scan_file_wide(
	          scanner,
	          scan_state,
	          wide_source,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_scan_file_wide(
	          NULL,
	          scan_state,
	          wide_source,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_file_wide(
	          scanner,
	          NULL,
	          wide_source,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_file_wide(
	          scanner,
	          scan_state,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	return( 0 );
}

#endif /* defined( HAVE_WIDE_CHARACTER_TYPE ) */

/* Tests the libsigscan_scanner_scan_file_io_handle function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner_scan_file_io_handle(
     const system_character_t *source )
{
	libbfio_handle_t *file_io_handle    = NULL;
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	libsigscan_scanner_t *scanner       = NULL;
	size_t string_length                = 0;
	int result                          = 0;

	/* Initialize test
	 */
	result = libbfio_file_initialize(
	          &file_io_handle,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

        SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
         "file_io_handle",
         file_io_handle );

        SIGSCAN_TEST_ASSERT_IS_NULL(
         "error",
         error );

	string_length = system_string_length(
	                 source );

#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = libbfio_file_set_name_wide(
	          file_io_handle,
	          source,
	          string_length,
	          &error );
#else
	result = libbfio_file_set_name(
	          file_io_handle,
	          source,
	          string_length,
	          &error );
#endif
	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

        SIGSCAN_TEST_ASSERT_IS_NULL(
         "error",
         error );

	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scanner_scan_file_io_handle(
	          scanner,
	          scan_state,
	          file_io_handle,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scanner_scan_file_io_handle(
	          NULL,
	          scan_state,
	          file_io_handle,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_file_io_handle(
	          scanner,
	          NULL,
	          file_io_handle,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scanner_scan_file_io_handle(
	          scanner,
	          scan_state,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libbfio_handle_free(
	          &file_io_handle,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
         "file_io_handle",
         file_io_handle );

        SIGSCAN_TEST_ASSERT_IS_NULL(
         "error",
         error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	if( file_io_handle != NULL )
	{
		libbfio_handle_free(
		 &file_io_handle,
		 NULL );
	}
	return( 0 );
}

/* Tests scanning a header signature
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner1(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	libsigscan_scanner_t *scanner       = NULL;
	int number_of_results               = 0;
	int result                          = 0;

	/* Initialize test
	 */
	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "test1",
	          6,
	          0,
	          (uint8_t *) "Client UrlCache MMF Ver ",
	          24,
	          LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_set_scan_buffer_size(
	          scanner,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_state_set_data_size(
	          scan_state,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_start(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_buffer(
	          scanner,
	          scan_state,
	          sigscan_test_scanner_data1,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_stop(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_get_number_of_results(
	          scan_state,
	          &number_of_results,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_results",
	 number_of_results,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	return( 0 );
}

/* Tests scanning a footer signature
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner2(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	libsigscan_scanner_t *scanner       = NULL;
	int number_of_results               = 0;
	int result                          = 0;

	/* Initialize test
	 */
	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_set_scan_buffer_size(
	          scanner,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "test1",
	          6,
	          8,
	          (uint8_t *) "conectix",
	          8,
	          LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_END,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_state_set_data_size(
	          scan_state,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_start(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_buffer(
	          scanner,
	          scan_state,
	          sigscan_test_scanner_data2,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_stop(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_get_number_of_results(
	          scan_state,
	          &number_of_results,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_results",
	 number_of_results,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	return( 0 );
}

/* Tests scanning an unbounded signature
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner3(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	libsigscan_scanner_t *scanner       = NULL;
	int number_of_results               = 0;
	int result                          = 0;

	/* Initialize test
	 */
	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_set_scan_buffer_size(
	          scanner,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "test1",
	          6,
	          0,
	          (uint8_t *) "example of unbounded pattern",
	          28,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_state_set_data_size(
	          scan_state,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_start(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_buffer(
	          scanner,
	          scan_state,
	          sigscan_test_scanner_data3,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_stop(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_get_number_of_results(
	          scan_state,
	          &number_of_results,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_results",
	 number_of_results,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Initialize test
	 */
	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_set_scan_buffer_size(
	          scanner,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "test1",
	          6,
	          0,
	          (uint8_t *) "example of unbounded pattern",
	          28,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "test2",
	          6,
	          0,
	          (uint8_t *) "another example",
	          15,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_state_set_data_size(
	          scan_state,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_start(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_buffer(
	          scanner,
	          scan_state,
	          sigscan_test_scanner_data3,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_stop(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_get_number_of_results(
	          scan_state,
	          &number_of_results,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_results",
	 number_of_results,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	return( 0 );
}

/* Tests scanning an unbounded signature
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scanner4(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	libsigscan_scanner_t *scanner       = NULL;
	int number_of_results               = 0;
	int result                          = 0;

	/* Initialize test
	 */
	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_set_scan_buffer_size(
	          scanner,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access0",
	          15,
	          0,
	          (uint8_t *) "\"CONNECT ",
	          9,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access1",
	          15,
	          0,
	          (uint8_t *) "\"DELETE ",
	          8,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access2",
	          15,
	          0,
	          (uint8_t *) "\"GET ",
	          5,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access3",
	          15,
	          0,
	          (uint8_t *) "\"HEAD ",
	          6,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access4",
	          15,
	          0,
	          (uint8_t *) " HTTP/",
	          6,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access5",
	          15,
	          0,
	          (uint8_t *) "\"OPTIONS ",
	          9,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access6",
	          15,
	          0,
	          (uint8_t *) "\"PATCH ",
	          7,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access7",
	          15,
	          0,
	          (uint8_t *) "\"POST ",
	          6,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access8",
	          15,
	          0,
	          (uint8_t *) "\"PUT ",
	          5,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "apache_access9",
	          15,
	          0,
	          (uint8_t *) "\"TRACE ",
	          7,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access0",
	          19,
	          0,
	          (uint8_t *) " CONNECT ",
	          9,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access1",
	          19,
	          0,
	          (uint8_t *) " DELETE ",
	          8,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access2",
	          19,
	          0,
	          (uint8_t *) " GET ",
	          5,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access3",
	          19,
	          0,
	          (uint8_t *) " HEAD ",
	          6,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access4",
	          19,
	          0,
	          (uint8_t *) " HTTP/",
	          6,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access5",
	          19,
	          0,
	          (uint8_t *) " OPTIONS ",
	          9,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access6",
	          19,
	          0,
	          (uint8_t *) " PATCH ",
	          7,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access7",
	          19,
	          0,
	          (uint8_t *) " POST ",
	          6,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access8",
	          19,
	          0,
	          (uint8_t *) " PUT ",
	          5,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_add_signature(
	          scanner,
	          "confluence_access9",
	          19,
	          0,
	          (uint8_t *) " TRACE ",
	          7,
	          LIBSIGSCAN_SIGNATURE_FLAG_NO_OFFSET,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_state_set_data_size(
	          scan_state,
	          64,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_start(
	          scanner,
	          scan_state,
	          &error );

SIGSCAN_TEST_FPRINT_ERROR( error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_buffer(
	          scanner,
	          scan_state,
	          sigscan_test_scanner_data3,
	          128,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_scan_stop(
	          scanner,
	          scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_state_get_number_of_results(
	          scan_state,
	          &number_of_results,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_results",
	 number_of_results,
	 0 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Clean up
	 */
	result = libsigscan_scan_state_free(
	          &scan_state,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_state",
	 scan_state );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
	return( 0 );
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc,
     wchar_t * const argv[] )
#else
int main(
     int argc,
     char * const argv[] )
#endif
{
	system_character_t *source    = NULL;
	system_integer_t option       = 0;

#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )
	libcerror_error_t *error      = NULL;
	libsigscan_scanner_t *scanner = NULL;
	int result                    = 0;
#endif

	while( ( option = sigscan_test_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "" ) ) ) != (system_integer_t) -1 )
	{
		switch( option )
		{
			case (system_integer_t) '?':
			default:
				fprintf(
				 stderr,
				 "Invalid argument: %" PRIs_SYSTEM ".\n",
				 argv[ optind - 1 ] );

				return( EXIT_FAILURE );
		}
	}
	if( optind < argc )
	{
		source = argv[ optind ];
	}
#if defined( HAVE_DEBUG_OUTPUT ) && defined( SIGSCAN_TEST_SCANNER_VERBOSE )
	libsigscan_notify_set_verbose(
	 1 );
	libsigscan_notify_set_stream(
	 stderr,
	 NULL );
#endif

	SIGSCAN_TEST_RUN(
	 "libsigscan_scanner_initialize",
	 sigscan_test_scanner_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_scanner_free",
	 sigscan_test_scanner_free );

#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	/* Initialize scanner for tests
	 */
	result = libsigscan_scanner_initialize(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scanner_signal_abort",
	 sigscan_test_scanner_signal_abort,
	 scanner );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scanner_set_scan_buffer_size",
	 sigscan_test_scanner_set_scan_buffer_size,
	 scanner );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scanner_add_signature",
	 sigscan_test_scanner_add_signature,
	 scanner );

	/* Make sure to run the start test before libsigscan_scanner_scan_buffer
	 */
	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scanner_scan_start",
	 sigscan_test_scanner_scan_start,
	 scanner );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scanner_scan_buffer",
	 sigscan_test_scanner_scan_buffer,
	 scanner );

	/* Make sure to run the stop test after libsigscan_scanner_scan_buffer
	 */
	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scanner_scan_stop",
	 sigscan_test_scanner_scan_stop,
	 scanner );

	/* Clean up
	 */
	result = libsigscan_scanner_free(
	          &scanner,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scanner",
	 scanner );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	if( source != NULL )
	{
		SIGSCAN_TEST_RUN_WITH_ARGS(
		 "libsigscan_scanner_scan_file",
		 sigscan_test_scanner_scan_file,
		 source );

#if defined( HAVE_WIDE_CHARACTER_TYPE )

		SIGSCAN_TEST_RUN_WITH_ARGS(
		 "libsigscan_scanner_scan_file_wide",
		 sigscan_test_scanner_scan_file_wide,
		 source );

#endif /* defined( HAVE_WIDE_CHARACTER_TYPE ) */

		SIGSCAN_TEST_RUN_WITH_ARGS(
		 "libsigscan_scanner_scan_file_io_handle",
		 sigscan_test_scanner_scan_file_io_handle,
		 source );
	}
#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */

	SIGSCAN_TEST_RUN(
	 "sigscan_test_scanner1",
	 sigscan_test_scanner1 );

	SIGSCAN_TEST_RUN(
	 "sigscan_test_scanner2",
	 sigscan_test_scanner2 );

	SIGSCAN_TEST_RUN(
	 "sigscan_test_scanner3",
	 sigscan_test_scanner3 );

	SIGSCAN_TEST_RUN(
	 "sigscan_test_scanner4",
	 sigscan_test_scanner4 );

	/* TODO add test to scan for unbounded signature on buffer boundary */

	return( EXIT_SUCCESS );

on_error:
#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scanner != NULL )
	{
		libsigscan_scanner_free(
		 &scanner,
		 NULL );
	}
#endif
	return( EXIT_FAILURE );
}

