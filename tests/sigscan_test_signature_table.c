/*
 * Library signature_table type test program
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

#include "sigscan_test_libcdata.h"
#include "sigscan_test_libcerror.h"
#include "sigscan_test_libsigscan.h"
#include "sigscan_test_macros.h"
#include "sigscan_test_memory.h"
#include "sigscan_test_unused.h"

#include "../libsigscan/libsigscan_definitions.h"
#include "../libsigscan/libsigscan_signature.h"
#include "../libsigscan/libsigscan_signature_table.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

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

	signature_table = NULL;

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
     libsigscan_signature_table_t *signature_table )
{
	libcerror_error_t *error        = NULL;
	int number_of_byte_value_groups = 0;
	int result                      = 0;

	/* Test regular cases
	 */
	result = libsigscan_signature_table_get_number_of_byte_value_groups(
	          signature_table,
	          &number_of_byte_value_groups,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "number_of_byte_value_groups",
	 number_of_byte_value_groups,
	 7 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libsigscan_signature_table_get_byte_value_group_by_index function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_get_byte_value_group_by_index(
     libsigscan_signature_table_t *signature_table )
{
	libcerror_error_t *error                        = NULL;
	libsigscan_byte_value_group_t *byte_value_group = NULL;
	int result                                      = 0;

	/* Test regular cases
	 */
	result = libsigscan_signature_table_get_byte_value_group_by_index(
	          signature_table,
	          0,
	          &byte_value_group,
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
	result = libsigscan_signature_table_get_byte_value_group_by_index(
	          NULL,
	          0,
	          &byte_value_group,
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

	result = libsigscan_signature_table_get_byte_value_group_by_index(
	          signature_table,
	          -1,
	          &byte_value_group,
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

	result = libsigscan_signature_table_get_byte_value_group_by_index(
	          signature_table,
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

/* Tests the libsigscan_signature_table_get_byte_value_group_by_offset function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_get_byte_value_group_by_offset(
     libsigscan_signature_table_t *signature_table )
{
	libcerror_error_t *error                        = NULL;
	libsigscan_byte_value_group_t *byte_value_group = NULL;
	int result                                      = 0;

	/* Test regular cases
	 */
	result = libsigscan_signature_table_get_byte_value_group_by_offset(
	          signature_table,
	          0,
	          &byte_value_group,
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
	result = libsigscan_signature_table_get_byte_value_group_by_offset(
	          NULL,
	          0,
	          &byte_value_group,
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

	result = libsigscan_signature_table_get_byte_value_group_by_offset(
	          signature_table,
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

/* Tests the libsigscan_signature_table_fill function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_fill(
     void )
{
	libcdata_list_t *offsets_ignore_list          = NULL;
	libcdata_list_t *signatures_list              = NULL;
	libcerror_error_t *error                      = NULL;
	libsigscan_signature_t *signature             = NULL;
	libsigscan_signature_table_t *signature_table = NULL;
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

	result = libcdata_list_initialize(
	          &offsets_ignore_list,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "offsets_ignore_list",
	 offsets_ignore_list );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_signature_table_fill(
	          signature_table,
	          signatures_list,
	          offsets_ignore_list,
	          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START,
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
	result = libsigscan_signature_table_fill(
	          NULL,
	          signatures_list,
	          offsets_ignore_list,
	          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START,
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

	result = libsigscan_signature_table_fill(
	          signature_table,
	          NULL,
	          offsets_ignore_list,
	          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START,
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
	          &offsets_ignore_list,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "offsets_ignore_list",
	 offsets_ignore_list );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

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
	if( offsets_ignore_list != NULL )
	{
		libcdata_list_free(
		 &offsets_ignore_list,
		 NULL,
		 NULL );
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
     libsigscan_signature_table_t *signature_table )
{
	libcerror_error_t *error = NULL;
	int number_of_signatures = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_signature_table_get_number_of_signatures(
	          signature_table,
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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libsigscan_signature_table_get_signatures_list_clone function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signature_table_get_signatures_list_clone(
     libsigscan_signature_table_t *signature_table )
{
	libcdata_list_t *signatures_list_clone = 0;
	libcerror_error_t *error               = NULL;
	int result                             = 0;

	/* Test regular cases
	 */
	result = libsigscan_signature_table_get_signatures_list_clone(
	          signature_table,
	          &signatures_list_clone,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Clean up
	 */
	result = libsigscan_signature_table_free_signatures_list_clone(
	          &signatures_list_clone,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "signatures_list_clone",
	 signatures_list_clone );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( signatures_list_clone != NULL )
	{
		libsigscan_signature_table_free_signatures_list_clone(
		 &signatures_list_clone,
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

	libcdata_list_t *offsets_ignore_list          = NULL;
	libcdata_list_t *signatures_list              = NULL;
	libcerror_error_t *error                      = NULL;
	libsigscan_signature_t *signature             = NULL;
	libsigscan_signature_table_t *signature_table = NULL;
	int result                                    = 0;

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */
#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argc )
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_table_initialize",
	 sigscan_test_signature_table_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_table_free",
	 sigscan_test_signature_table_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_signature_table_fill",
	 sigscan_test_signature_table_fill );

	/* TODO: add tests for libsigscan_signature_table_free_signatures_list_clone */

	/* TODO: add tests for libsigscan_signature_table_insert_signature */

#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	/* Initialize signature_table for tests
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

	result = libcdata_list_initialize(
	          &offsets_ignore_list,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "offsets_ignore_list",
	 offsets_ignore_list );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_signature_table_fill(
	          signature_table,
	          signatures_list,
	          offsets_ignore_list,
	          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START,
	          0,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_signature_table_get_number_of_byte_value_groups",
	 sigscan_test_signature_table_get_number_of_byte_value_groups,
	 signature_table );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_signature_table_get_byte_value_group_by_index",
	 sigscan_test_signature_table_get_byte_value_group_by_index,
	 signature_table );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_signature_table_get_byte_value_group_by_offset",
	 sigscan_test_signature_table_get_byte_value_group_by_offset,
	 signature_table );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_signature_table_get_number_of_signatures",
	 sigscan_test_signature_table_get_number_of_signatures,
	 signature_table );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_signature_table_get_signatures_list_clone",
	 sigscan_test_signature_table_get_signatures_list_clone,
	 signature_table );

	/* Clean up
	 */
	result = libcdata_list_free(
	          &offsets_ignore_list,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "offsets_ignore_list",
	 offsets_ignore_list );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

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
	if( offsets_ignore_list != NULL )
	{
		libcdata_list_free(
		 &offsets_ignore_list,
		 NULL,
		 NULL );
	}
	if( signatures_list != NULL )
	{
		libcdata_list_free(
		 &signatures_list,
		 (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_signature_free,
		 NULL );
	}
	if( signature_table != NULL )
	{
		libsigscan_signature_table_free(
		 &signature_table,
		 NULL );
	}
#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */

	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */
}

