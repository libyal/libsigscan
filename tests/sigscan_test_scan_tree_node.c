/*
 * Library scan_tree_node type test program
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

#include "../libsigscan/libsigscan_scan_tree_node.h"

#if defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT )

/* Tests the libsigscan_scan_tree_node_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_scan_tree_node_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libsigscan_scan_tree_node_free(
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

	/* TODO: add tests for libsigscan_scan_tree_node_initialize */

	SIGSCAN_TEST_RUN(
	 "libsigscan_scan_tree_node_free",
	 sigscan_test_scan_tree_node_free );

	/* TODO: add tests for libsigscan_scan_tree_node_set_byte_value */

	/* TODO: add tests for libsigscan_scan_tree_node_set_default_value */

	/* TODO: add tests for libsigscan_scan_tree_node_get_scan_object */

	/* TODO: add tests for libsigscan_scan_tree_node_scan_buffer */

	/* TODO: add tests for libsigscan_scan_tree_node_printf */

#endif /* defined( __GNUC__ ) && !defined( LIBSIGSCAN_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

