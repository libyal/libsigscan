/*
 * Library scan_state type test program
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "sigscan_test_libcdata.h"
#include "sigscan_test_libcerror.h"
#include "sigscan_test_libsigscan.h"
#include "sigscan_test_macros.h"
#include "sigscan_test_memory.h"
#include "sigscan_test_unused.h"

#include "../libsigscan/libsigscan_definitions.h"
#include "../libsigscan/libsigscan_scan_state.h"
#include "../libsigscan/libsigscan_scan_tree.h"
#include "../libsigscan/libsigscan_scan_tree_node.h"
#include "../libsigscan/libsigscan_signature.h"

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
     libsigscan_scan_state_t *scan_state )
{
	libcerror_error_t *error = NULL;
	size_t buffer_size       = 0;
	int result               = 0;

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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libsigscan_scan_state_get_header_range function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_get_header_range(
     libsigscan_scan_state_t *scan_state )
{
	libcerror_error_t *error    = NULL;
	uint64_t header_range_end   = 0;
	uint64_t header_range_size  = 0;
	uint64_t header_range_start = 0;
	int result                  = 0;

	/* Test regular cases
	 */
	result = libsigscan_scan_state_get_header_range(
	          scan_state,
	          &header_range_start,
	          &header_range_end,
	          &header_range_size,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scan_state_get_header_range(
	          NULL,
	          &header_range_start,
	          &header_range_end,
	          &header_range_size,
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

	result = libsigscan_scan_state_get_header_range(
	          scan_state,
	          NULL,
	          &header_range_end,
	          &header_range_size,
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

	result = libsigscan_scan_state_get_header_range(
	          scan_state,
	          &header_range_start,
	          NULL,
	          &header_range_size,
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

	result = libsigscan_scan_state_get_header_range(
	          scan_state,
	          &header_range_start,
	          &header_range_end,
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

/* Tests the libsigscan_scan_state_get_footer_range function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_get_footer_range(
     libsigscan_scan_state_t *scan_state )
{
	libcerror_error_t *error    = NULL;
	uint64_t footer_range_end   = 0;
	uint64_t footer_range_size  = 0;
	uint64_t footer_range_start = 0;
	int result                  = 0;

	/* Test regular cases
	 */
	result = libsigscan_scan_state_get_footer_range(
	          scan_state,
	          &footer_range_start,
	          &footer_range_end,
	          &footer_range_size,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_scan_state_get_footer_range(
	          NULL,
	          &footer_range_start,
	          &footer_range_end,
	          &footer_range_size,
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

	result = libsigscan_scan_state_get_footer_range(
	          scan_state,
	          NULL,
	          &footer_range_end,
	          &footer_range_size,
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

	result = libsigscan_scan_state_get_footer_range(
	          scan_state,
	          &footer_range_start,
	          NULL,
	          &footer_range_size,
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

	result = libsigscan_scan_state_get_footer_range(
	          scan_state,
	          &footer_range_start,
	          &footer_range_end,
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

/* Tests the libsigscan_scan_state_start function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_start(
     libsigscan_scan_state_t *scan_state )
{
	libcerror_error_t *error                 = NULL;
	libsigscan_scan_tree_t *footer_scan_tree = NULL;
	libsigscan_scan_tree_t *header_scan_tree = NULL;
	libsigscan_scan_tree_t *scan_tree        = NULL;
	int result                               = 0;

	/* Initialize test
	 */
	result = libsigscan_scan_tree_initialize(
	          &header_scan_tree,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "header_scan_tree",
	 header_scan_tree );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_tree_initialize(
	          &footer_scan_tree,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "footer_scan_tree",
	 footer_scan_tree );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_tree_initialize(
	          &scan_tree,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_tree",
	 scan_tree );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_state_start(
	          scan_state,
	          header_scan_tree,
	          footer_scan_tree,
	          scan_tree,
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
	result = libsigscan_scan_state_start(
	          NULL,
	          header_scan_tree,
	          footer_scan_tree,
	          scan_tree,
	          64,
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

	result = libsigscan_scan_state_start(
	          scan_state,
	          NULL,
	          footer_scan_tree,
	          scan_tree,
	          64,
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

	result = libsigscan_scan_state_start(
	          scan_state,
	          header_scan_tree,
	          NULL,
	          scan_tree,
	          64,
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

	result = libsigscan_scan_state_start(
	          scan_state,
	          header_scan_tree,
	          footer_scan_tree,
	          NULL,
	          64,
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
	result = libsigscan_scan_tree_free(
	          &scan_tree,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_tree",
	 scan_tree );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_tree_free(
	          &footer_scan_tree,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "footer_scan_tree",
	 footer_scan_tree );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_tree_free(
	          &header_scan_tree,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "header_scan_tree",
	 header_scan_tree );

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
	if( scan_tree != NULL )
	{
		libsigscan_scan_tree_free(
		 &scan_tree,
		 NULL );
	}
	if( footer_scan_tree != NULL )
	{
		libsigscan_scan_tree_free(
		 &footer_scan_tree,
		 NULL );
	}
	if( header_scan_tree != NULL )
	{
		libsigscan_scan_tree_free(
		 &header_scan_tree,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scan_state_flush function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_flush(
     libsigscan_scan_state_t *scan_state )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_scan_state_flush(
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
	result = libsigscan_scan_state_flush(
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

/* Tests the libsigscan_scan_state_stop function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_stop(
     libsigscan_scan_state_t *scan_state )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_scan_state_stop(
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
	result = libsigscan_scan_state_stop(
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

/* Tests the libsigscan_internal_scan_state_scan_buffer_by_scan_tree function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_internal_scan_state_scan_buffer_by_scan_tree(
     libsigscan_scan_state_t *scan_state )
{
	uint8_t buffer[ 128 ];

	libcdata_list_t *signatures_list         = NULL;
	libcerror_error_t *error                 = NULL;
	libsigscan_scan_tree_t *scan_tree        = NULL;
	libsigscan_scan_tree_node_t *active_node = NULL;
	libsigscan_signature_t *signature        = NULL;
	void *memcpy_result                      = NULL;
	void *memset_result                      = NULL;
	int result                               = 0;

	/* Initialize test
	 */
	memset_result = memory_set(
	                 buffer,
	                 0,
	                 sizeof( uint8_t ) * 128 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	memcpy_result = memory_copy(
	                 buffer,
	                 "pattern",
	                 sizeof( uint8_t ) * 7 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "memcpy_result",
	 memcpy_result );

	result = libsigscan_scan_tree_initialize(
	          &scan_tree,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "scan_tree",
	 scan_tree );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libcdata_list_initialize(
	          &signatures_list,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "signatures_list",
	 signatures_list );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_signature_initialize(
	          &signature,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "signature",
	 signature );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_signature_set(
	          signature,
	          "test",
	          4,
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

	result = libcdata_list_append_value(
	          signatures_list,
	          (intptr_t *) signature,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	signature = NULL;

	result = libsigscan_scan_tree_build(
	          scan_tree,
	          signatures_list,
	          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START,
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
	active_node = scan_tree->root_node;

	result = libsigscan_internal_scan_state_scan_buffer_by_scan_tree(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          scan_tree,
	          &active_node,
	          0,
	          buffer,
	          128,
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
	result = libsigscan_internal_scan_state_scan_buffer_by_scan_tree(
	          NULL,
	          scan_tree,
	          &active_node,
	          0,
	          buffer,
	          128,
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

	result = libsigscan_internal_scan_state_scan_buffer_by_scan_tree(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          NULL,
	          &active_node,
	          0,
	          buffer,
	          128,
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

	result = libsigscan_internal_scan_state_scan_buffer_by_scan_tree(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          scan_tree,
	          NULL,
	          0,
	          buffer,
	          128,
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

	result = libsigscan_internal_scan_state_scan_buffer_by_scan_tree(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          scan_tree,
	          &active_node,
	          0,
	          NULL,
	          128,
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

	/* Clean up
	 */
	result = libcdata_list_free(
	          &signatures_list,
	          (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_signature_free,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signatures_list",
	 signatures_list );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_scan_tree_free(
	          &scan_tree,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_tree",
	 scan_tree );

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
	if( signature != NULL )
	{
		libsigscan_signature_free(
		 &signature,
		 NULL );
	}
	if( signatures_list != NULL )
	{
		libcdata_list_free(
		 &signatures_list,
		 (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_signature_free,
		 NULL );
	}
	if( scan_tree != NULL )
	{
		libsigscan_scan_tree_free(
		 &scan_tree,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_internal_scan_state_scan_buffer function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_internal_scan_state_scan_buffer(
     libsigscan_scan_state_t *scan_state )
{
	uint8_t buffer[ 128 ];

	libcerror_error_t *error = NULL;
	void *memcpy_result      = NULL;
	void *memset_result      = NULL;
	int result               = 0;

	/* Initialize test
	 */
	memset_result = memory_set(
	                 buffer,
	                 0,
	                 sizeof( uint8_t ) * 128 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	memcpy_result = memory_copy(
	                 buffer,
	                 "pattern",
	                 sizeof( uint8_t ) * 7 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "memcpy_result",
	 memcpy_result );

	/* Test regular cases
	 */
	result = libsigscan_internal_scan_state_scan_buffer(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          0,
	          buffer,
	          128,
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
	result = libsigscan_internal_scan_state_scan_buffer(
	          NULL,
	          0,
	          buffer,
	          128,
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

	result = libsigscan_internal_scan_state_scan_buffer(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          0,
	          NULL,
	          128,
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

	result = libsigscan_internal_scan_state_scan_buffer(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          0,
	          buffer,
	          0,
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

	result = libsigscan_internal_scan_state_scan_buffer(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          0,
	          buffer,
	          (size_t) SSIZE_MAX + 1,
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

	result = libsigscan_internal_scan_state_scan_buffer(
	          (libsigscan_internal_scan_state_t *) scan_state,
	          0,
	          buffer,
	          128,
	          1024,
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

/* Tests the libsigscan_scan_state_scan_buffer function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_scan_buffer(
     libsigscan_scan_state_t *scan_state )
{
	uint8_t buffer[ 128 ];

	libcerror_error_t *error = NULL;
	void *memcpy_result      = NULL;
	void *memset_result      = NULL;
	int result               = 0;

	/* Initialize test
	 */
	memset_result = memory_set(
	                 buffer,
	                 0,
	                 sizeof( uint8_t ) * 128 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	memcpy_result = memory_copy(
	                 buffer,
	                 "pattern",
	                 sizeof( uint8_t ) * 7 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "memcpy_result",
	 memcpy_result );

	/* Test regular cases
	 */
	result = libsigscan_scan_state_scan_buffer(
	          scan_state,
	          0,
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
	result = libsigscan_scan_state_scan_buffer(
	          NULL,
	          0,
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

	result = libsigscan_scan_state_scan_buffer(
	          scan_state,
	          0,
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

	result = libsigscan_scan_state_scan_buffer(
	          scan_state,
	          0,
	          buffer,
	          (size_t) SSIZE_MAX + 1,
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

/* Tests the libsigscan_scan_state_get_number_of_results function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_get_number_of_results(
     libsigscan_scan_state_t *scan_state )
{
	libcerror_error_t *error = NULL;
	int number_of_results    = 0;
	int result               = 0;

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

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_results",
	 number_of_results,
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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libsigscan_scan_state_get_result function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_state_get_result(
     libsigscan_scan_state_t *scan_state )
{
	libcerror_error_t *error              = NULL;
	libsigscan_scan_result_t *scan_result = 0;
	int result                            = 0;

	/* Test regular cases
	 */
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

	/* Clean up
	 */
	result = libsigscan_scan_result_free(
	          &scan_result,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "scan_result",
	 scan_result );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( scan_result != NULL )
	{
		libsigscan_scan_result_free(
		 &scan_result,
		 NULL );
	}
	return( 0 );
}

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

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
#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )
#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	libcerror_error_t *error            = NULL;
	libsigscan_scan_state_t *scan_state = NULL;
	int result                          = 0;

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */
#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argc )
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_initialize",
	 sigscan_test_scan_state_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_free",
	 sigscan_test_scan_state_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_state_set_data_size",
	 sigscan_test_scan_state_set_data_size );

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )
#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	/* Initialize scan_state for tests
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

	/* Make sure to run the start test first
	 */
	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_start",
	 sigscan_test_scan_state_start,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_flush",
	 sigscan_test_scan_state_flush,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_get_buffer_size",
	 sigscan_test_scan_state_get_buffer_size,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_get_header_range",
	 sigscan_test_scan_state_get_header_range,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_get_footer_range",
	 sigscan_test_scan_state_get_footer_range,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_internal_scan_state_scan_buffer_by_scan_tree",
	 sigscan_test_internal_scan_state_scan_buffer_by_scan_tree,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_internal_scan_state_scan_buffer",
	 sigscan_test_internal_scan_state_scan_buffer,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_scan_buffer",
	 sigscan_test_scan_state_scan_buffer,
	 scan_state );

	/* Make sure to run the stop test before libsigscan_scan_state_get_number_of_results
	 * and libsigscan_scan_state_get_result
	 */
	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_stop",
	 sigscan_test_scan_state_stop,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_get_number_of_results",
	 sigscan_test_scan_state_get_number_of_results,
	 scan_state );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_state_get_result",
	 sigscan_test_scan_state_get_result,
	 scan_state );

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

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */
#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

on_error:
#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )
#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )
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
#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */
#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	return( EXIT_FAILURE );
}

