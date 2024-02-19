/*
 * Library offsets_list type test program
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

#include "../libsigscan/libsigscan_offsets_list.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_offset_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_offset_free(
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

/* Tests the libsigscan_offset_clone function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offset_clone(
     void )
{
	libcerror_error_t *error    = NULL;
	off64_t *destination_offset = NULL;
	off64_t source_offset       = 0;
	int result                  = 0;

	/* Test regular cases
	 */
	result = libsigscan_offset_clone(
	          &destination_offset,
	          &source_offset,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NOT_NULL(
	 "destination_offset",
	 destination_offset );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	memory_free(
	 destination_offset );

	destination_offset = NULL;

	result = libsigscan_offset_clone(
	          &destination_offset,
	          NULL,
	          &error );

	SIGSCAN_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "destination_offset",
	 destination_offset );

	SIGSCAN_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libsigscan_offset_clone(
	          NULL,
	          &source_offset,
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

	destination_offset = (off64_t *) 0x12345678UL;

	result = libsigscan_offset_clone(
	          &destination_offset,
	          &source_offset,
	          &error );

	destination_offset = NULL;

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

/* Tests the libsigscan_offsets_list_compare function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_offsets_list_compare(
     void )
{
	libcerror_error_t *error = NULL;
	off64_t first_offset     = 0;
	off64_t second_offset    = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = libsigscan_offsets_list_compare(
	          &first_offset,
	          &second_offset,
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
	result = libsigscan_offsets_list_compare(
	          NULL,
	          &second_offset,
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

	result = libsigscan_offsets_list_compare(
	          &first_offset,
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
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argc )
	SIGSCAN_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

	SIGSCAN_TEST_RUN(
	 "libsigscan_offset_free",
	 sigscan_test_offset_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_offset_clone",
	 sigscan_test_offset_clone );

	SIGSCAN_TEST_RUN(
	 "libsigscan_offsets_list_compare",
	 sigscan_test_offsets_list_compare );

	/* TODO: add tests for libsigscan_offsets_list_has_offset */

	/* TODO: add tests for libsigscan_offsets_list_insert_offset */

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */
}

