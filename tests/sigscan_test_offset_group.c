/*
 * Library offset_group type test program
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

#include "../libsigscan/libsigscan_offset_group.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_offset_group_initialize function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_group_initialize(
     void )
{
	libcerror_error_t *error                = NULL;
	libsigscan_offset_group_t *offset_group = NULL;
	int result                              = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests         = 1;
	int number_of_memset_fail_tests         = 1;
	int test_number                         = 0;
#endif

	/* Test regular cases
	 */
	result = libsigscan_offset_group_initialize(
	          &offset_group,
	          1,
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

	result = libsigscan_offset_group_free(
	          &offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "offset_group",
	 offset_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_offset_group_initialize(
	          NULL,
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

	offset_group = (libsigscan_offset_group_t *) 0x12345678UL;

	result = libsigscan_offset_group_initialize(
	          &offset_group,
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

	offset_group = NULL;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libsigscan_offset_group_initialize with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_offset_group_initialize(
		          &offset_group,
		          1,
		          &error );

		if( sigscan_test_malloc_attempts_before_fail != -1 )
		{
			sigscan_test_malloc_attempts_before_fail = -1;

			if( offset_group != NULL )
			{
				libsigscan_offset_group_free(
				 &offset_group,
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
			 "offset_group",
			 offset_group );

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
		/* Test libsigscan_offset_group_initialize with memset failing
		 */
		sigscan_test_memset_attempts_before_fail = test_number;

		result = libsigscan_offset_group_initialize(
		          &offset_group,
		          1,
		          &error );

		if( sigscan_test_memset_attempts_before_fail != -1 )
		{
			sigscan_test_memset_attempts_before_fail = -1;

			if( offset_group != NULL )
			{
				libsigscan_offset_group_free(
				 &offset_group,
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
			 "offset_group",
			 offset_group );

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
	if( offset_group != NULL )
	{
		libsigscan_offset_group_free(
		 &offset_group,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_offset_group_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_group_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_offset_group_free(
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

/* Tests the libsigscan_offset_group_compare function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_group_compare(
     void )
{
	libcerror_error_t *error                       = NULL;
	libsigscan_offset_group_t *first_offset_group  = NULL;
	libsigscan_offset_group_t *second_offset_group = NULL;
	int result                                     = 0;

	/* Initialize test
	 */
	result = libsigscan_offset_group_initialize(
	          &first_offset_group,
	          1,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "first_offset_group",
	 first_offset_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_offset_group_initialize(
	          &second_offset_group,
	          1,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "second_offset_group",
	 second_offset_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_offset_group_compare(
	          first_offset_group,
	          second_offset_group,
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
	result = libsigscan_offset_group_compare(
	          NULL,
	          second_offset_group,
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

	result = libsigscan_offset_group_compare(
	          first_offset_group,
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
	result = libsigscan_offset_group_free(
	          &second_offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "second_offset_group",
	 second_offset_group );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_offset_group_free(
	          &first_offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "first_offset_group",
	 first_offset_group );

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
	if( second_offset_group != NULL )
	{
		libsigscan_offset_group_free(
		 &second_offset_group,
		 NULL );
	}
	if( first_offset_group != NULL )
	{
		libsigscan_offset_group_free(
		 &first_offset_group,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_offset_group_get_weight function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_group_get_weight(
     void )
{
	libcerror_error_t *error                = NULL;
	libsigscan_offset_group_t *offset_group = NULL;
	int result                              = 0;
	int weight                              = 0;

	/* Initialize test
	 */
	result = libsigscan_offset_group_initialize(
	          &offset_group,
	          1,
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

	/* Test regular cases
	 */
	result = libsigscan_offset_group_get_weight(
	          offset_group,
	          &weight,
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
	result = libsigscan_offset_group_get_weight(
	          NULL,
	          &weight,
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

	result = libsigscan_offset_group_get_weight(
	          offset_group,
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
	result = libsigscan_offset_group_free(
	          &offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "offset_group",
	 offset_group );

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
	if( offset_group != NULL )
	{
		libsigscan_offset_group_free(
		 &offset_group,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_offset_group_get_number_of_offsets function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_group_get_number_of_offsets(
     void )
{
	libcerror_error_t *error                = NULL;
	libsigscan_offset_group_t *offset_group = NULL;
	int number_of_offsets                   = 0;
	int result                              = 0;

	/* Initialize test
	 */
	result = libsigscan_offset_group_initialize(
	          &offset_group,
	          1,
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

	/* Test regular cases
	 */
	result = libsigscan_offset_group_get_number_of_offsets(
	          offset_group,
	          &number_of_offsets,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_offsets",
	 number_of_offsets,
	 0 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Initialize test
	 */
	result = libsigscan_offset_group_append_offset(
	          offset_group,
	          0,
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
	result = libsigscan_offset_group_get_number_of_offsets(
	          offset_group,
	          &number_of_offsets,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_offsets",
	 number_of_offsets,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_offset_group_get_number_of_offsets(
	          NULL,
	          &number_of_offsets,
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

	result = libsigscan_offset_group_get_number_of_offsets(
	          offset_group,
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
	result = libsigscan_offset_group_free(
	          &offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "offset_group",
	 offset_group );

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
	if( offset_group != NULL )
	{
		libsigscan_offset_group_free(
		 &offset_group,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_offset_group_get_offset_by_index function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_group_get_offset_by_index(
     void )
{
	libcerror_error_t *error                = NULL;
	libsigscan_offset_group_t *offset_group = NULL;
	off64_t offset_by_index                 = 0;
	int result                              = 0;

	/* Initialize test
	 */
	result = libsigscan_offset_group_initialize(
	          &offset_group,
	          1,
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

	result = libsigscan_offset_group_append_offset(
	          offset_group,
	          0,
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
	result = libsigscan_offset_group_get_offset_by_index(
	          offset_group,
	          0,
	          &offset_by_index,
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
	result = libsigscan_offset_group_get_offset_by_index(
	          NULL,
	          0,
	          &offset_by_index,
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

	result = libsigscan_offset_group_get_offset_by_index(
	          offset_group,
	          -1,
	          &offset_by_index,
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

	result = libsigscan_offset_group_get_offset_by_index(
	          offset_group,
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

	/* Clean up
	 */
	result = libsigscan_offset_group_free(
	          &offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "offset_group",
	 offset_group );

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
	if( offset_group != NULL )
	{
		libsigscan_offset_group_free(
		 &offset_group,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_offset_group_append_offset function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_group_append_offset(
     void )
{
	libcerror_error_t *error                = NULL;
	libsigscan_offset_group_t *offset_group = NULL;
	int result                              = 0;

	/* Initialize test
	 */
	result = libsigscan_offset_group_initialize(
	          &offset_group,
	          1,
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

	/* Test regular cases
	 */
	result = libsigscan_offset_group_append_offset(
	          offset_group,
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
	result = libsigscan_offset_group_append_offset(
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

#if defined( HAVE_SIGSCAN_TEST_MEMORY )

	/* Test libsigscan_offset_group_append_offset with malloc failing
	 */
	sigscan_test_malloc_attempts_before_fail = 0;

	result = libsigscan_offset_group_append_offset(
	          offset_group,
	          0,
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
	result = libsigscan_offset_group_free(
	          &offset_group,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "offset_group",
	 offset_group );

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
	if( offset_group != NULL )
	{
		libsigscan_offset_group_free(
		 &offset_group,
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
	 "libsigscan_offset_group_initialize",
	 sigscan_test_offset_group_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_offset_group_free",
	 sigscan_test_offset_group_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_offset_group_compare",
	 sigscan_test_offset_group_compare );

	SIGSCAN_TEST_RUN(
	 "libsigscan_offset_group_get_weight",
	 sigscan_test_offset_group_get_weight );

	SIGSCAN_TEST_RUN(
	 "libsigscan_offset_group_get_number_of_offsets",
	 sigscan_test_offset_group_get_number_of_offsets );

	SIGSCAN_TEST_RUN(
	 "libsigscan_offset_group_get_offset_by_index",
	 sigscan_test_offset_group_get_offset_by_index );

	SIGSCAN_TEST_RUN(
	 "libsigscan_offset_group_append_offset",
	 sigscan_test_offset_group_append_offset );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

