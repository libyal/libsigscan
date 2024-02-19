/*
 * Library identifier type test program
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

#include "sigscan_test_libcerror.h"
#include "sigscan_test_libsigscan.h"
#include "sigscan_test_macros.h"
#include "sigscan_test_memory.h"
#include "sigscan_test_unused.h"

#include "../libsigscan/libsigscan_identifier.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_identifier_initialize function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_identifier_initialize(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_identifier_t *identifier = NULL;
	int result                          = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests     = 1;
	int number_of_memset_fail_tests     = 1;
	int test_number                     = 0;
#endif

	/* Test regular cases
	 */
	result = libsigscan_identifier_initialize(
	          &identifier,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "identifier",
	 identifier );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_identifier_free(
	          &identifier,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "identifier",
	 identifier );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_identifier_initialize(
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

	identifier = (libsigscan_identifier_t *) 0x12345678UL;

	result = libsigscan_identifier_initialize(
	          &identifier,
	          &error );

	identifier = NULL;

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
		/* Test libsigscan_identifier_initialize with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_identifier_initialize(
		          &identifier,
		          &error );

		if( sigscan_test_malloc_attempts_before_fail != -1 )
		{
			sigscan_test_malloc_attempts_before_fail = -1;

			if( identifier != NULL )
			{
				libsigscan_identifier_free(
				 &identifier,
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
			 "identifier",
			 identifier );

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
		/* Test libsigscan_identifier_initialize with memset failing
		 */
		sigscan_test_memset_attempts_before_fail = test_number;

		result = libsigscan_identifier_initialize(
		          &identifier,
		          &error );

		if( sigscan_test_memset_attempts_before_fail != -1 )
		{
			sigscan_test_memset_attempts_before_fail = -1;

			if( identifier != NULL )
			{
				libsigscan_identifier_free(
				 &identifier,
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
			 "identifier",
			 identifier );

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
	if( identifier != NULL )
	{
		libsigscan_identifier_free(
		 &identifier,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_identifier_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_identifier_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_identifier_free(
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

/* Tests the libsigscan_identifier_set function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_identifier_set(
     void )
{
	libcerror_error_t *error            = NULL;
	libsigscan_identifier_t *identifier = NULL;
	int result                          = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests     = 1;
	int test_number                     = 0;

#if defined( OPTIMIZATION_DISABLED )
	int number_of_memcpy_fail_tests     = 1;
#endif
#endif /* defined( HAVE_SIGSCAN_TEST_MEMORY ) */

	/* Initialize test
	 */
	result = libsigscan_identifier_initialize(
	          &identifier,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "identifier",
	 identifier );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_identifier_set(
	          identifier,
	          "test",
	          4,
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
	result = libsigscan_identifier_set(
	          identifier,
	          "test",
	          4,
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
	result = libsigscan_identifier_free(
	          &identifier,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "identifier",
	 identifier );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Initialize test
	 */
	result = libsigscan_identifier_initialize(
	          &identifier,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "identifier",
	 identifier );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_identifier_set(
	          NULL,
	          "test",
	          4,
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

	result = libsigscan_identifier_set(
	          identifier,
	          NULL,
	          4,
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

	result = libsigscan_identifier_set(
	          identifier,
	          "test",
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

	result = libsigscan_identifier_set(
	          identifier,
	          "test",
	          (size_t) MEMORY_MAXIMUM_ALLOCATION_SIZE + 1,
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

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libsigscan_identifier_set with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_identifier_set(
		          identifier,
		          "test",
		          4,
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
	}
#if defined( OPTIMIZATION_DISABLED )
	for( test_number = 0;
	     test_number < number_of_memcpy_fail_tests;
	     test_number++ )
	{
		/* Test libsigscan_identifier_set with memcpy failing
		 */
		sigscan_test_memcpy_attempts_before_fail = test_number;

		result = libsigscan_identifier_set(
		          identifier,
		          "test",
		          4,
		          &error );

		if( sigscan_test_memcpy_attempts_before_fail != -1 )
		{
			sigscan_test_memcpy_attempts_before_fail = -1;
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
	}
#endif /* defined( OPTIMIZATION_DISABLED ) */
#endif /* defined( HAVE_SIGSCAN_TEST_MEMORY ) */

	/* Clean up
	 */
	result = libsigscan_identifier_free(
	          &identifier,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "identifier",
	 identifier );

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
	if( identifier != NULL )
	{
		libsigscan_identifier_free(
		 &identifier,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_identifier_get_string_size function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_identifier_get_string_size(
     libsigscan_identifier_t *identifier )
{
	libcerror_error_t *error = NULL;
	size_t string_size       = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_identifier_get_string_size(
	          identifier,
	          &string_size,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_SIZE(
	 "string_size",
	 string_size,
	 (size_t) 5 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_identifier_get_string_size(
	          NULL,
	          &string_size,
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

	result = libsigscan_identifier_get_string_size(
	          identifier,
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

/* Tests the libsigscan_identifier_get_string function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_identifier_get_string(
     libsigscan_identifier_t *identifier )
{
	char string[ 16 ];

	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_identifier_get_string(
	          identifier,
	          string,
	          16,
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
	result = libsigscan_identifier_get_string(
	          NULL,
	          string,
	          16,
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

	result = libsigscan_identifier_get_string(
	          identifier,
	          NULL,
	          16,
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

	result = libsigscan_identifier_get_string(
	          identifier,
	          string,
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

	result = libsigscan_identifier_get_string(
	          identifier,
	          string,
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

#if defined( HAVE_SIGSCAN_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libsigscan_identifier_get_string with memcpy failing
	 */
	sigscan_test_memcpy_attempts_before_fail = 0;

	result = libsigscan_identifier_get_string(
	          identifier,
	          string,
	          16,
	          &error );

	if( sigscan_test_memcpy_attempts_before_fail != -1 )
	{
		sigscan_test_memcpy_attempts_before_fail = -1;
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
#endif /* defined( HAVE_SIGSCAN_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
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
	libsigscan_identifier_t *identifier = NULL;
	int result                          = 0;

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */
#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argc )
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

	SIGSCAN_TEST_RUN(
	 "libsigscan_identifier_initialize",
	 sigscan_test_identifier_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_identifier_free",
	 sigscan_test_identifier_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_identifier_set",
	 sigscan_test_identifier_set );

#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	/* Initialize identifier for tests
	 */
	result = libsigscan_identifier_initialize(
	          &identifier,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "identifier",
	 identifier );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_identifier_set(
	          identifier,
	          "test",
	          4,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_identifier_get_string_size",
	 sigscan_test_identifier_get_string_size,
	 identifier );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_identifier_get_string",
	 sigscan_test_identifier_get_string,
	 identifier );

	/* Clean up
	 */
	result = libsigscan_identifier_free(
	          &identifier,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "identifier",
	 identifier );

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
	if( identifier != NULL )
	{
		libsigscan_identifier_free(
		 &identifier,
		 NULL );
	}
#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */

	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */
}

