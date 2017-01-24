/*
 * Library signature_table type test program
 *
 * Copyright (C) 2014-2017, Joachim Metz <joachim.metz@gmail.com>
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "sigscan_test_libcerror.h"
#include "sigscan_test_libsigscan.h"
#include "sigscan_test_macros.h"
#include "sigscan_test_memory.h"
#include "sigscan_test_unused.h"

#include "../libsigscan/libsigscan_signature_table.h"

#if defined( __GNUC__ )

/* Tests the libsigscan_signature_table_initialize function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_initialize(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_signature_table_t *signature_table = NULL;
	int result                                    = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests               = 1;
	int number_of_memset_fail_tests               = 1;
	int test_number                               = 0;
#endif

	/* Test regular cases
	 */
	result = libsigscan_signature_table_initialize(
	          &signature_table,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

        SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
         "signature_table",
         signature_table );

        SIGSCAN_TEST_ASSERT_IS_NULL(
         "error",
         error );

	result = libsigscan_signature_table_free(
	          &signature_table,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

        SIGSCAN_TEST_ASSERT_IS_NULL(
         "signature_table",
         signature_table );

        SIGSCAN_TEST_ASSERT_IS_NULL(
         "error",
         error );

	/* Test error cases
	 */
	result = libsigscan_signature_table_initialize(
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

	signature_table = (libsigscan_signature_table_t *) 0x12345678UL;

	result = libsigscan_signature_table_initialize(
	          &signature_table,
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

	signature_table = NULL;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libsigscan_signature_table_initialize with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_signature_table_initialize(
		          &signature_table,
		          &error );

		if( sigscan_test_malloc_attempts_before_fail != -1 )
		{
			sigscan_test_malloc_attempts_before_fail = -1;

			if( signature_table != NULL )
			{
				libsigscan_signature_table_free(
				 &signature_table,
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
			 "signature_table",
			 signature_table );

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
		/* Test libsigscan_signature_table_initialize with memset failing
		 */
		sigscan_test_memset_attempts_before_fail = test_number;

		result = libsigscan_signature_table_initialize(
		          &signature_table,
		          &error );

		if( sigscan_test_memset_attempts_before_fail != -1 )
		{
			sigscan_test_memset_attempts_before_fail = -1;

			if( signature_table != NULL )
			{
				libsigscan_signature_table_free(
				 &signature_table,
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
			 "signature_table",
			 signature_table );

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
	if( signature_table != NULL )
	{
		libsigscan_signature_table_free(
		 &signature_table,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_signature_table_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_signature_table_free(
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

/* Tests the libsigscan_signature_table_get_number_of_byte_value_groups function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_get_number_of_byte_value_groups(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_signature_table_t *signature_table = NULL;
	int number_of_byte_value_groups               = 0;
	int number_of_byte_value_groups_is_set        = 0;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_signature_table_initialize(
	          &signature_table,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "signature_table",
	 signature_table );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_signature_table_get_number_of_byte_value_groups(
	          signature_table,
	          &number_of_byte_value_groups,
	          &error );

	SIGSCAN_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	number_of_byte_value_groups_is_set = result;

	/* Test error cases
	 */
	result = libsigscan_signature_table_get_number_of_byte_value_groups(
	          NULL,
	          &number_of_byte_value_groups,
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

	if( number_of_byte_value_groups_is_set != 0 )
	{
		result = libsigscan_signature_table_get_number_of_byte_value_groups(
		          signature_table,
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
	}
	/* Clean up
	 */
	result = libsigscan_signature_table_free(
	          &signature_table,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signature_table",
	 signature_table );

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
	if( signature_table != NULL )
	{
		libsigscan_signature_table_free(
		 &signature_table,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_signature_table_get_number_of_signatures function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_get_number_of_signatures(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_signature_table_t *signature_table = NULL;
	int number_of_signatures                      = 0;
	int number_of_signatures_is_set               = 0;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_signature_table_initialize(
	          &signature_table,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "signature_table",
	 signature_table );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_signature_table_get_number_of_signatures(
	          signature_table,
	          &number_of_signatures,
	          &error );

	SIGSCAN_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	number_of_signatures_is_set = result;

	/* Test error cases
	 */
	result = libsigscan_signature_table_get_number_of_signatures(
	          NULL,
	          &number_of_signatures,
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

	if( number_of_signatures_is_set != 0 )
	{
		result = libsigscan_signature_table_get_number_of_signatures(
		          signature_table,
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
	}
	/* Clean up
	 */
	result = libsigscan_signature_table_free(
	          &signature_table,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signature_table",
	 signature_table );

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
	if( signature_table != NULL )
	{
		libsigscan_signature_table_free(
		 &signature_table,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_signature_table_get_signatures_list_clone function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_get_signatures_list_clone(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_signature_table_t *signature_table = NULL;
	libcdata_list_t *signatures_list_clone        = 0;
	int result                                    = 0;
	int signatures_list_clone_is_set              = 0;

	/* Initialize test
	 */
	result = libsigscan_signature_table_initialize(
	          &signature_table,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "signature_table",
	 signature_table );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_signature_table_get_signatures_list_clone(
	          signature_table,
	          &signatures_list_clone,
	          &error );

	SIGSCAN_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	signatures_list_clone_is_set = result;

	/* Test error cases
	 */
	result = libsigscan_signature_table_get_signatures_list_clone(
	          NULL,
	          &signatures_list_clone,
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

	if( signatures_list_clone_is_set != 0 )
	{
		result = libsigscan_signature_table_get_signatures_list_clone(
		          signature_table,
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
	}
	/* Clean up
	 */
	result = libsigscan_signature_table_free(
	          &signature_table,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signature_table",
	 signature_table );

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
	if( signature_table != NULL )
	{
		libsigscan_signature_table_free(
		 &signature_table,
		 NULL );
	}
	return( 0 );
}

#endif /* defined( __GNUC__ ) */

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

#if defined( __GNUC__ )

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_table_initialize",
	 sigscan_test_signature_table_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_table_free",
	 sigscan_test_signature_table_free );

	/* TODO: add tests for libsigscan_signature_table_fill */

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_table_get_number_of_byte_value_groups",
	 sigscan_test_signature_table_get_number_of_byte_value_groups );

	/* TODO: add tests for libsigscan_signature_table_get_byte_value_group_by_index */

	/* TODO: add tests for libsigscan_signature_table_get_byte_value_group_by_offset */

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_table_get_number_of_signatures",
	 sigscan_test_signature_table_get_number_of_signatures );

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_table_get_signatures_list_clone",
	 sigscan_test_signature_table_get_signatures_list_clone );

	/* TODO: add tests for libsigscan_signature_table_insert_signature */

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

