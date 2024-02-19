/*
 * Library signatures_list type test program
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

#include "../libsigscan/libsigscan_signature.h"
#include "../libsigscan/libsigscan_signatures_list.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_signatures_list_remove_signature function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_signatures_list_remove_signature(
     void )
{
	libcdata_list_t *signatures_list  = NULL;
	libcerror_error_t *error          = NULL;
	libsigscan_signature_t *signature = NULL;
	int result                        = 0;

	/* Initialize test
	 */
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

	/* Test regular cases
	 */
	result = libsigscan_signatures_list_remove_signature(
	          signatures_list,
	          signature,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Initialize test
	 */
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

	/* Test error cases
	 */
	result = libsigscan_signatures_list_remove_signature(
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

	result = libcdata_list_free(
	          &signatures_list,
	          NULL,
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
		 NULL,
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
	 "libsigscan_signatures_list_remove_signature",
	 sigscan_test_signatures_list_remove_signature );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */
}

