/*
 * Library pattern_weights type test program
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

#include "../libsigscan/libsigscan_pattern_weights.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_pattern_weights_initialize function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_initialize(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	int result                                    = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests               = 1;
	int number_of_memset_fail_tests               = 1;
	int test_number                               = 0;
#endif

	/* Test regular cases
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_pattern_weights_initialize(
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

	pattern_weights = (libsigscan_pattern_weights_t *) 0x12345678UL;

	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	pattern_weights = NULL;

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
		/* Test libsigscan_pattern_weights_initialize with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_pattern_weights_initialize(
		          &pattern_weights,
		          &error );

		if( sigscan_test_malloc_attempts_before_fail != -1 )
		{
			sigscan_test_malloc_attempts_before_fail = -1;

			if( pattern_weights != NULL )
			{
				libsigscan_pattern_weights_free(
				 &pattern_weights,
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
			 "pattern_weights",
			 pattern_weights );

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
		/* Test libsigscan_pattern_weights_initialize with memset failing
		 */
		sigscan_test_memset_attempts_before_fail = test_number;

		result = libsigscan_pattern_weights_initialize(
		          &pattern_weights,
		          &error );

		if( sigscan_test_memset_attempts_before_fail != -1 )
		{
			sigscan_test_memset_attempts_before_fail = -1;

			if( pattern_weights != NULL )
			{
				libsigscan_pattern_weights_free(
				 &pattern_weights,
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
			 "pattern_weights",
			 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_pattern_weights_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_pattern_weights_free(
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

/* Tests the libsigscan_pattern_weights_add_weight function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_add_weight(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_pattern_weights_add_weight(
	          pattern_weights,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_add_weight(
	          NULL,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_pattern_weights_set_weight function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_set_weight(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_pattern_weights_set_weight(
	          pattern_weights,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_set_weight(
	          NULL,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_pattern_weights_get_largest_weight function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_get_largest_weight(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	int largest_weight                            = 0;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_pattern_weights_get_largest_weight(
	          pattern_weights,
	          &largest_weight,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_add_weight(
	          pattern_weights,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_get_largest_weight(
	          pattern_weights,
	          &largest_weight,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "largest_weight",
	 largest_weight,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_pattern_weights_get_largest_weight(
	          NULL,
	          &largest_weight,
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

	result = libsigscan_pattern_weights_get_largest_weight(
	          pattern_weights,
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
	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_pattern_weights_get_offset_group function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_get_offset_group(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_offset_group_t *offset_group       = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	offset_group = NULL;

	result = libsigscan_pattern_weights_get_offset_group(
	          pattern_weights,
	          1,
	          &offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_add_weight(
	          pattern_weights,
	          0,
	          1,
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
	offset_group = NULL;

	result = libsigscan_pattern_weights_get_offset_group(
	          pattern_weights,
	          1,
	          &offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "offset_group",
	 offset_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	offset_group = NULL;

	result = libsigscan_pattern_weights_get_offset_group(
	          NULL,
	          1,
	          &offset_group,
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
	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_pattern_weights_insert_offset function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_insert_offset(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_pattern_weights_insert_offset(
	          pattern_weights,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_insert_offset(
	          NULL,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_pattern_weights_get_weight_group function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_get_weight_group(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	libsigscan_weight_group_t *weight_group       = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	weight_group = NULL;

	result = libsigscan_pattern_weights_get_weight_group(
	          pattern_weights,
	          0,
	          &weight_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_add_weight(
	          pattern_weights,
	          0,
	          1,
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
	weight_group = NULL;

	result = libsigscan_pattern_weights_get_weight_group(
	          pattern_weights,
	          0,
	          &weight_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "weight_group",
	 weight_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	weight_group = NULL;

	result = libsigscan_pattern_weights_get_weight_group(
	          NULL,
	          0,
	          &weight_group,
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
	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_pattern_weights_insert_add_weight function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_insert_add_weight(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_pattern_weights_insert_add_weight(
	          pattern_weights,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_insert_add_weight(
	          NULL,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_pattern_weights_insert_set_weight function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_pattern_weights_insert_set_weight(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_pattern_weights_t *pattern_weights = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "pattern_weights",
	 pattern_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_pattern_weights_insert_set_weight(
	          pattern_weights,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_insert_set_weight(
	          NULL,
	          0,
	          1,
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
	result = libsigscan_pattern_weights_free(
	          &pattern_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "pattern_weights",
	 pattern_weights );

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
	if( pattern_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &pattern_weights,
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
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argc )
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_initialize",
	 sigscan_test_pattern_weights_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_free",
	 sigscan_test_pattern_weights_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_add_weight",
	 sigscan_test_pattern_weights_add_weight );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_set_weight",
	 sigscan_test_pattern_weights_set_weight );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_get_largest_weight",
	 sigscan_test_pattern_weights_get_largest_weight );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_get_offset_group",
	 sigscan_test_pattern_weights_get_offset_group );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_insert_offset",
	 sigscan_test_pattern_weights_insert_offset );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_get_weight_group",
	 sigscan_test_pattern_weights_get_weight_group );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_insert_add_weight",
	 sigscan_test_pattern_weights_insert_add_weight );

	SIGSCAN_TEST_RUN(
	 "libsigscan_pattern_weights_insert_set_weight",
	 sigscan_test_pattern_weights_insert_set_weight );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

