/*
 * Library scan_tree type test program
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
#include "../libsigscan/libsigscan_pattern_weights.h"
#include "../libsigscan/libsigscan_signature.h"
#include "../libsigscan/libsigscan_signature_table.h"
#include "../libsigscan/libsigscan_scan_tree.h"
#include "../libsigscan/libsigscan_scan_tree_node.h"
#include "../libsigscan/libsigscan_signature.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_scan_tree_initialize function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_initialize(
     void )
{
	libcerror_error_t *error          = NULL;
	libsigscan_scan_tree_t *scan_tree = NULL;
	int result                        = 0;

#if defined( HAVE_SIGSCAN_TEST_MEMORY )
	int number_of_malloc_fail_tests   = 1;
	int number_of_memset_fail_tests   = 1;
	int test_number                   = 0;
#endif

	/* Test regular cases
	 */
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

	/* Test error cases
	 */
	result = libsigscan_scan_tree_initialize(
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

	scan_tree = (libsigscan_scan_tree_t *) 0x12345678UL;

	result = libsigscan_scan_tree_initialize(
	          &scan_tree,
	          &error );

	scan_tree = NULL;

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
		/* Test libsigscan_scan_tree_initialize with malloc failing
		 */
		sigscan_test_malloc_attempts_before_fail = test_number;

		result = libsigscan_scan_tree_initialize(
		          &scan_tree,
		          &error );

		if( sigscan_test_malloc_attempts_before_fail != -1 )
		{
			sigscan_test_malloc_attempts_before_fail = -1;

			if( scan_tree != NULL )
			{
				libsigscan_scan_tree_free(
				 &scan_tree,
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
			 "scan_tree",
			 scan_tree );

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
		/* Test libsigscan_scan_tree_initialize with memset failing
		 */
		sigscan_test_memset_attempts_before_fail = test_number;

		result = libsigscan_scan_tree_initialize(
		          &scan_tree,
		          &error );

		if( sigscan_test_memset_attempts_before_fail != -1 )
		{
			sigscan_test_memset_attempts_before_fail = -1;

			if( scan_tree != NULL )
			{
				libsigscan_scan_tree_free(
				 &scan_tree,
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
			 "scan_tree",
			 scan_tree );

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
	if( scan_tree != NULL )
	{
		libsigscan_scan_tree_free(
		 &scan_tree,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scan_tree_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_scan_tree_free(
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

/* Tests the libsigscan_scan_tree_build function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_build(
     void )
{
	libcdata_list_t *signatures_list  = NULL;
	libcerror_error_t *error          = NULL;
	libsigscan_scan_tree_t *scan_tree = NULL;
	libsigscan_signature_t *signature = NULL;
	int result                        = 0;

	/* Initialize test
	 */
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

	/* Test regular cases
	 */
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

	/* Test error cases
	 */
	result = libsigscan_scan_tree_build(
	          NULL,
	          signatures_list,
	          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START,
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

	result = libsigscan_scan_tree_build(
	          scan_tree,
	          NULL,
	          LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START,
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

	result = libsigscan_scan_tree_build(
	          scan_tree,
	          signatures_list,
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

/* Tests the libsigscan_scan_tree_get_pattern_offset_by_byte_value_weights function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_get_pattern_offset_by_byte_value_weights(
     libsigscan_scan_tree_t *scan_tree )
{
	libcerror_error_t *error                         = NULL;
	libsigscan_pattern_weights_t *byte_value_weights = NULL;
	off64_t pattern_offset                           = 0;
	int result                                       = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &byte_value_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "byte_value_weights",
	 byte_value_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_tree_get_pattern_offset_by_byte_value_weights(
	          scan_tree,
	          byte_value_weights,
	          &pattern_offset,
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
	result = libsigscan_scan_tree_get_pattern_offset_by_byte_value_weights(
	          NULL,
	          byte_value_weights,
	          &pattern_offset,
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
	          &byte_value_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "byte_value_weights",
	 byte_value_weights );

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
	if( byte_value_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &byte_value_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scan_tree_get_pattern_offset_by_occurrence_weights function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_get_pattern_offset_by_occurrence_weights(
     libsigscan_scan_tree_t *scan_tree )
{
	libcerror_error_t *error                         = NULL;
	libsigscan_pattern_weights_t *byte_value_weights = NULL;
	libsigscan_pattern_weights_t *occurrence_weights = NULL;
	off64_t pattern_offset                           = 0;
	int result                                       = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &occurrence_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "occurrence_weights",
	 occurrence_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_initialize(
	          &byte_value_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "byte_value_weights",
	 byte_value_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_tree_get_pattern_offset_by_occurrence_weights(
	          scan_tree,
	          occurrence_weights,
	          byte_value_weights,
	          &pattern_offset,
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
	result = libsigscan_scan_tree_get_pattern_offset_by_occurrence_weights(
	          NULL,
	          occurrence_weights,
	          byte_value_weights,
	          &pattern_offset,
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
	          &byte_value_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "byte_value_weights",
	 byte_value_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_free(
	          &occurrence_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "occurrence_weights",
	 occurrence_weights );

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
	if( byte_value_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &byte_value_weights,
		 NULL );
	}
	if( occurrence_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &occurrence_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scan_tree_get_pattern_offset_by_similarity_weights function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_get_pattern_offset_by_similarity_weights(
     libsigscan_scan_tree_t *scan_tree )
{
	libcerror_error_t *error                         = NULL;
	libsigscan_pattern_weights_t *byte_value_weights = NULL;
	libsigscan_pattern_weights_t *occurrence_weights = NULL;
	libsigscan_pattern_weights_t *similarity_weights = NULL;
	off64_t pattern_offset                           = 0;
	int result                                       = 0;

	/* Initialize test
	 */
	result = libsigscan_pattern_weights_initialize(
	          &similarity_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "similarity_weights",
	 similarity_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_initialize(
	          &occurrence_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "occurrence_weights",
	 occurrence_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_initialize(
	          &byte_value_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "byte_value_weights",
	 byte_value_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_tree_get_pattern_offset_by_similarity_weights(
	          scan_tree,
	          similarity_weights,
	          occurrence_weights,
	          byte_value_weights,
	          &pattern_offset,
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
	result = libsigscan_scan_tree_get_pattern_offset_by_similarity_weights(
	          NULL,
	          similarity_weights,
	          occurrence_weights,
	          byte_value_weights,
	          &pattern_offset,
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
	          &byte_value_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "byte_value_weights",
	 byte_value_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_free(
	          &occurrence_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "occurrence_weights",
	 occurrence_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_free(
	          &similarity_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "similarity_weights",
	 similarity_weights );

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
	if( byte_value_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &byte_value_weights,
		 NULL );
	}
	if( occurrence_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &occurrence_weights,
		 NULL );
	}
	if( similarity_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &similarity_weights,
		 NULL );
	}
	return( 0 );
}

/* Tests the libsigscan_scan_tree_get_most_significant_pattern_offset function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_get_most_significant_pattern_offset(
     libsigscan_scan_tree_t *scan_tree )
{
	libcerror_error_t *error                         = NULL;
	libsigscan_signature_table_t *signature_table    = NULL;
	libsigscan_pattern_weights_t *byte_value_weights = NULL;
	libsigscan_pattern_weights_t *occurrence_weights = NULL;
	libsigscan_pattern_weights_t *similarity_weights = NULL;
	off64_t pattern_offset                           = 0;
	int result                                       = 0;

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

	result = libsigscan_pattern_weights_initialize(
	          &similarity_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "similarity_weights",
	 similarity_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_initialize(
	          &occurrence_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "occurrence_weights",
	 occurrence_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_initialize(
	          &byte_value_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "byte_value_weights",
	 byte_value_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libsigscan_scan_tree_get_most_significant_pattern_offset(
	          scan_tree,
	          signature_table,
	          similarity_weights,
	          occurrence_weights,
	          byte_value_weights,
	          &pattern_offset,
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
	result = libsigscan_scan_tree_get_most_significant_pattern_offset(
	          NULL,
	          signature_table,
	          similarity_weights,
	          occurrence_weights,
	          byte_value_weights,
	          &pattern_offset,
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
	          &byte_value_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "byte_value_weights",
	 byte_value_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_free(
	          &occurrence_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "occurrence_weights",
	 occurrence_weights );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libsigscan_pattern_weights_free(
	          &similarity_weights,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "similarity_weights",
	 similarity_weights );

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
	if( byte_value_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &byte_value_weights,
		 NULL );
	}
	if( occurrence_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &occurrence_weights,
		 NULL );
	}
	if( similarity_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &similarity_weights,
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

/* Tests the libsigscan_scan_tree_get_spanning_range function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_get_spanning_range(
     libsigscan_scan_tree_t *scan_tree )
{
	libcerror_error_t *error = NULL;
	uint64_t range_size      = 0;
	uint64_t range_start     = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_scan_tree_get_spanning_range(
	          scan_tree,
	          &range_size,
	          &range_start,
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
	result = libsigscan_scan_tree_get_spanning_range(
	          NULL,
	          &range_start,
	          &range_size,
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

	result = libsigscan_scan_tree_get_spanning_range(
	          scan_tree,
	          NULL,
	          &range_size,
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

	result = libsigscan_scan_tree_get_spanning_range(
	          scan_tree,
	          &range_start,
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

	libcdata_list_t *signatures_list  = NULL;
	libcerror_error_t *error          = NULL;
	libsigscan_scan_tree_t *scan_tree = NULL;
	libsigscan_signature_t *signature = NULL;
	int result                        = 0;

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */
#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argc )
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_tree_initialize",
	 sigscan_test_scan_tree_initialize );

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_tree_free",
	 sigscan_test_scan_tree_free );

	/* TODO: add tests for libsigscan_scan_tree_build_node */

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_tree_build",
	 sigscan_test_scan_tree_build );

	/* TODO: add tests for libsigscan_scan_tree_fill_pattern_weights */

	/* TODO: add tests for libsigscan_scan_tree_fill_range_list */

#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	/* Initialize scan_tree for tests
	 */
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

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_tree_get_pattern_offset_by_byte_value_weights",
	 sigscan_test_scan_tree_get_pattern_offset_by_byte_value_weights,
	 scan_tree );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_tree_get_pattern_offset_by_occurrence_weights",
	 sigscan_test_scan_tree_get_pattern_offset_by_occurrence_weights,
	 scan_tree );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_tree_get_pattern_offset_by_similarity_weights",
	 sigscan_test_scan_tree_get_pattern_offset_by_similarity_weights,
	 scan_tree );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_tree_get_most_significant_pattern_offset",
	 sigscan_test_scan_tree_get_most_significant_pattern_offset,
	 scan_tree );

	SIGSCAN_TEST_RUN_WITH_ARGS(
	 "libsigscan_scan_tree_get_spanning_range",
	 sigscan_test_scan_tree_get_spanning_range,
	 scan_tree );

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
#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */

	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */
}

