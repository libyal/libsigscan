/*
 * Library signature_group type test program
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "sigscan_test_libcerror.h"
#include "sigscan_test_libsigscan.h"
#include "sigscan_test_macros.h"
#include "sigscan_test_memory.h"
#include "sigscan_test_unused.h"

#include "../libsigscan/libsigscan_signature.h"
#include "../libsigscan/libsigscan_signature_group.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_signature_group_initialize function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_group_initialize(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_signature_group_t *signature_group = NULL;
	int result                                    = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests               = 2;
	int number_of_memset_fail_tests               = 1;
	int test_number                               = 0;
#endif

	/* Test regular cases
	 */
	result = libsigscan_signature_group_initialize(
	          &signature_group,
	          (uint8_t) 't',
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "signature_group",
	 signature_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_signature_group_free(
	          &signature_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signature_group",
	 signature_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_signature_group_initialize(
	          NULL,
	          (uint8_t) 't',
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

	signature_group = (libsigscan_signature_group_t *) 0x12345678UL;

	result = libsigscan_signature_group_initialize(
	          &signature_group,
	          (uint8_t) 't',
	          &error );

	signature_group = NULL;

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
		/* Test libsigscan_signature_group_initialize with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_signature_group_initialize(
		          &signature_group,
		          (uint8_t) 't',
		          &error );

		if( sigscan_test_malloc_attempts_before_fail != -1 )
		{
			sigscan_test_malloc_attempts_before_fail = -1;

			if( signature_group != NULL )
			{
				libsigscan_signature_group_free(
				 &signature_group,
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
			 "signature_group",
			 signature_group );

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
		/* Test libsigscan_signature_group_initialize with memset failing
		 */
		sigscan_test_memset_attempts_before_fail = test_number;

		result = libsigscan_signature_group_initialize(
		          &signature_group,
		          (uint8_t) 't',
		          &error );

		if( sigscan_test_memset_attempts_before_fail != -1 )
		{
			sigscan_test_memset_attempts_before_fail = -1;

			if( signature_group != NULL )
			{
				libsigscan_signature_group_free(
				 &signature_group,
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
			 "signature_group",
			 signature_group );

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
	if( signature_group != NULL )
	{
		libsigscan_signature_group_free(
		 &signature_group,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_signature_group_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_group_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_signature_group_free(
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

/* Tests the libsigscan_signature_group_compare function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_group_compare(
     void )
{
	libcerror_error_t *error                             = NULL;
	libsigscan_signature_group_t *first_signature_group  = NULL;
	libsigscan_signature_group_t *second_signature_group = NULL;
	int result                                           = 0;

	/* Initialize test
	 */
	result = libsigscan_signature_group_initialize(
	          &first_signature_group,
	          (uint8_t) 't',
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "first_signature_group",
	 first_signature_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_signature_group_initialize(
	          &second_signature_group,
	          (uint8_t) 't',
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "second_signature_group",
	 second_signature_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_signature_group_compare(
	          first_signature_group,
	          second_signature_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 LIBCDATA_COMPARE_EQUAL );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_signature_group_compare(
	          NULL,
	          second_signature_group,
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

	result = libsigscan_signature_group_compare(
	          first_signature_group,
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
	result = libsigscan_signature_group_free(
	          &second_signature_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "second_signature_group",
	 second_signature_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_signature_group_free(
	          &first_signature_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "first_signature_group",
	 first_signature_group );

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
	if( second_signature_group != NULL )
	{
		libsigscan_signature_group_free(
		 &second_signature_group,
		 NULL );
	}
	if( first_signature_group != NULL )
	{
		libsigscan_signature_group_free(
		 &first_signature_group,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_signature_group_get_byte_value function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_group_get_byte_value(
     libsigscan_signature_group_t *signature_group )
{
	libcerror_error_t *error = NULL;
	uint8_t byte_value       = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_signature_group_get_byte_value(
	          signature_group,
	          &byte_value,
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
	result = libsigscan_signature_group_get_byte_value(
	          NULL,
	          &byte_value,
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

	result = libsigscan_signature_group_get_byte_value(
	          signature_group,
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

/* Tests the libsigscan_signature_group_get_number_of_signatures function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_group_get_number_of_signatures(
     libsigscan_signature_group_t *signature_group )
{
	libcerror_error_t *error = NULL;
	int number_of_signatures = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_signature_group_get_number_of_signatures(
	          signature_group,
	          &number_of_signatures,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_signatures",
	 number_of_signatures,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_signature_group_get_number_of_signatures(
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

	result = libsigscan_signature_group_get_number_of_signatures(
	          signature_group,
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

/* Tests the libsigscan_signature_group_get_signature_by_index function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_group_get_signature_by_index(
     libsigscan_signature_group_t *signature_group )
{
	libcerror_error_t *error          = NULL;
	libsigscan_signature_t *signature = NULL;
	int result                        = 0;

	/* Test regular cases
	 */
	result = libsigscan_signature_group_get_signature_by_index(
	          signature_group,
	          0,
	          &signature,
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
	result = libsigscan_signature_group_get_signature_by_index(
	          NULL,
	          0,
	          &signature,
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

	result = libsigscan_signature_group_get_signature_by_index(
	          signature_group,
	          -1,
	          &signature,
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

	result = libsigscan_signature_group_get_signature_by_index(
	          signature_group,
	          0,
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

/* Tests the libsigscan_signature_group_append_signature function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_group_append_signature(
     void )
{
	libcerror_error_t *error                      = NULL;
	libsigscan_signature_t *signature             = NULL;
	libsigscan_signature_group_t *signature_group = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libsigscan_signature_group_initialize(
	          &signature_group,
	          1,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "signature_group",
	 signature_group );

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

	/* Test regular cases
	 */
	result = libsigscan_signature_group_append_signature(
	          signature_group,
	          signature,
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
	result = libsigscan_signature_group_append_signature(
	          NULL,
	          signature,
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

	result = libsigscan_signature_group_append_signature(
	          signature_group,
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

#if defined( HAVE_SIGSCAN_TEST_MEMORY )

	/* Test libsigscan_signature_group_append_signature with malloc failing
	 */
	sigscan_test_malloc_attempts_before_fail = 0;

	result = libsigscan_signature_group_append_signature(
	          signature_group,
	          signature,
	          &error );

	if( sigscan_test_malloc_attempts_before_fail != -1 )
	{
		sigscan_test_malloc_attempts_before_fail = -1;
	}
	else
	{
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
#endif /* defined( HAVE_SIGSCAN_TEST_MEMORY ) */

	/* Clean up
	 */
	result = libsigscan_signature_free(
	          &signature,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signature",
	 signature );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_signature_group_free(
	          &signature_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signature_group",
	 signature_group );

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
	if( signature_group != NULL )
	{
		libsigscan_signature_group_free(
		 &signature_group,
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

	libcerror_error_t *error                      = NULL;
	libsigscan_signature_t *signature             = NULL;
	libsigscan_signature_group_t *signature_group = NULL;
	int result                                    = 0;

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */
#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argc )
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_group_initialize",
	 sigscan_test_signature_group_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_group_free",
	 sigscan_test_signature_group_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_group_compare",
	 sigscan_test_signature_group_compare );

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_group_append_signature",
	 sigscan_test_signature_group_append_signature );

#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	/* Initialize signature_group for tests
	 */
	result = libsigscan_signature_group_initialize(
	          &signature_group,
	          (uint8_t) 't',
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "signature_group",
	 signature_group );

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

	result = libsigscan_signature_group_append_signature(
	          signature_group,
	          signature,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_signature_group_get_byte_value",
	 sigscan_test_signature_group_get_byte_value,
	 signature_group );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_signature_group_get_number_of_signatures",
	 sigscan_test_signature_group_get_number_of_signatures,
	 signature_group );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_signature_group_get_signature_by_index",
	 sigscan_test_signature_group_get_signature_by_index,
	 signature_group );

	/* Clean up
	 */
	result = libsigscan_signature_free(
	          &signature,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signature",
	 signature );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_signature_group_free(
	          &signature_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signature_group",
	 signature_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */
#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

on_error:
#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )
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
	if( signature_group != NULL )
	{
		libsigscan_signature_group_free(
		 &signature_group,
		 NULL );
	}
#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */

	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */
}

