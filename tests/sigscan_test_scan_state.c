/*
 * Library scan_state type test program
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "sigscan_test_libcerror.h"
#include "sigscan_test_libsigscan.h"
#include "sigscan_test_macros.h"
#include "sigscan_test_memory.h"
#include "sigscan_test_unused.h"

#include "../libsigscan/libsigscan_scan_state.h"

/* Tests the libsigscan_scan_state_initialize function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_initialize(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	int result                          = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests     = 1;
	int number_of_memset_fail_tests     = 1;
	int test_number                     = 0;
#endif

	/* Test regular cases
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

	/* Test error cases
	 */
	result = libsigscan_scan_state_initialize(
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

	scan_state = (libsigscan_scan_state_t *) 0x12345678UL;

	result = libsigscan_scan_state_initialize(
	          &scan_state,
	          &error );

	scan_state = NULL;

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
		/* Test libsigscan_scan_state_initialize with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_scan_state_initialize(
		          &scan_state,
		          &error );

		if( sigscan_test_malloc_attempts_before_fail != -1 )
		{
			sigscan_test_malloc_attempts_before_fail = -1;

			if( scan_state != NULL )
			{
				libsigscan_scan_state_free(
				 &scan_state,
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
			 "scan_state",
			 scan_state );

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
		/* Test libsigscan_scan_state_initialize with memset failing
		 */
		sigscan_test_memset_attempts_before_fail = test_number;

		result = libsigscan_scan_state_initialize(
		          &scan_state,
		          &error );

		if( sigscan_test_memset_attempts_before_fail != -1 )
		{
			sigscan_test_memset_attempts_before_fail = -1;

			if( scan_state != NULL )
			{
				libsigscan_scan_state_free(
				 &scan_state,
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
			 "scan_state",
			 scan_state );

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
	if( scan_state != NULL )
	{
		libsigscan_scan_state_free(
		 &scan_state,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scan_state_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_scan_state_free(
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

/* Tests the libsigscan_scan_state_set_data_offset function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_set_data_offset(
     void )
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
	result = libsigscan_scan_state_set_data_offset(
	          scan_state,
	          0,
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
	result = libsigscan_scan_state_set_data_offset(
	          NULL,
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

	result = libsigscan_scan_state_set_data_offset(
	          scan_state,
	          -1,
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

/* Tests the libsigscan_scan_state_set_data_size function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_set_data_size(
     void )
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

	/* Test error cases
	 */
	result = libsigscan_scan_state_set_data_size(
	          NULL,
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

	result = libsigscan_scan_state_set_data_size(
	          scan_state,
	          (size64_t) INT64_MAX + 1,
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

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_scan_state_get_buffer_size function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_get_buffer_size(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	size_t buffer_size                  = 0;
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
	result = libsigscan_scan_state_get_buffer_size(
	          scan_state,
	          &buffer_size,
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
	result = libsigscan_scan_state_get_buffer_size(
	          NULL,
	          &buffer_size,
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

	result = libsigscan_scan_state_get_buffer_size(
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

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

/* Tests the libsigscan_scan_state_get_number_of_results function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_get_number_of_results(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	int number_of_results               = 0;
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
	result = libsigscan_scan_state_get_number_of_results(
	          scan_state,
	          &number_of_results,
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
	result = libsigscan_scan_state_get_number_of_results(
	          NULL,
	          &number_of_results,
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

	result = libsigscan_scan_state_get_number_of_results(
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

/* Tests the libsigscan_scan_state_get_result function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_get_result(
     void )
{
	libcerror_error_t *error              = NULL;
	libsigscan_scan_result_t *scan_result = 0;
	libsigscan_scan_state_t *scan_state   = NULL;
	int result                            = 0;

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
#ifdef TODO
/* TODO change test to work */
	scan_result = NULL;

	result = libsigscan_scan_state_get_result(
	          scan_state,
	          0,
	          &scan_result,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_result",
	 scan_result );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );
#endif

	/* Test error cases
	 */
	scan_result = NULL;

	result = libsigscan_scan_state_get_result(
	          NULL,
	          0,
	          &scan_result,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_result",
	 scan_result );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scan_state_get_result(
	          scan_state,
	          -1,
	          &scan_result,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_result",
	 scan_result );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libsigscan_scan_state_get_result(
	          scan_state,
	          0,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_result",
	 scan_result );

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

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc SIGSCAN_TEST_ATTRIBUTE_UNUSED,
     wchar_t * const argv[] SIGSCAN_TEST_ATTRIBUTE_UNUSED )
#else
int main(
     int argc SIGSCAN_TEST_ATTRIBUTE_UNUSED,
     char * const argv[] SIGSCAN_TEST_ATTRIBUTE_UNUSED )
#endif
{
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argc )
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_initialize",
	 sigscan_test_scan_state_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_free",
	 sigscan_test_scan_state_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_set_data_offset",
	 sigscan_test_scan_state_set_data_offset );

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_set_data_size",
	 sigscan_test_scan_state_set_data_size );

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_get_buffer_size",
	 sigscan_test_scan_state_get_buffer_size );

	/* TODO: add tests for libsigscan_scan_state_get_header_range */

	/* TODO: add tests for libsigscan_scan_state_get_footer_range */

	/* TODO: add tests for libsigscan_scan_state_start */

	/* TODO: add tests for libsigscan_scan_state_stop */

	/* TODO: add tests for libsigscan_scan_state_flush */

	/* TODO: add tests for libsigscan_scan_state_scan_buffer */

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_get_number_of_results",
	 sigscan_test_scan_state_get_number_of_results );

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_get_result",
	 sigscan_test_scan_state_get_result );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

