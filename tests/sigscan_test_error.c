/*
 * Library error functions test program
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
#include "sigscan_test_unused.h"

/* Tests the libsigscan_error_free function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_error_free(
     void )
{
	/* Test invocation of function only
	 */
	libsigscan_error_free(
	 NULL );

	return( 1 );
}

/* Tests the libsigscan_error_fprint function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_error_fprint(
     void )
{
	/* Test invocation of function only
	 */
	libsigscan_error_fprint(
	 NULL,
	 NULL );

	return( 1 );
}

/* Tests the libsigscan_error_sprint function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_error_sprint(
     void )
{
	/* Test invocation of function only
	 */
	libsigscan_error_sprint(
	 NULL,
	 NULL,
	 0 );

	return( 1 );
}

/* Tests the libsigscan_error_backtrace_fprint function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_error_backtrace_fprint(
     void )
{
	/* Test invocation of function only
	 */
	libsigscan_error_backtrace_fprint(
	 NULL,
	 NULL );

	return( 1 );
}

/* Tests the libsigscan_error_backtrace_sprint function
 * Returns 1 if successful or 0 if not
 */
int sigscan_test_error_backtrace_sprint(
     void )
{
	/* Test invocation of function only
	 */
	libsigscan_error_backtrace_sprint(
	 NULL,
	 NULL,
	 0 );

	return( 1 );
}

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

	SIGSCAN_TEST_RUN(
	 "libsigscan_error_free",
	 sigscan_test_error_free );

	SIGSCAN_TEST_RUN(
	 "libsigscan_error_fprint",
	 sigscan_test_error_fprint );

	SIGSCAN_TEST_RUN(
	 "libsigscan_error_sprint",
	 sigscan_test_error_sprint );

	SIGSCAN_TEST_RUN(
	 "libsigscan_error_backtrace_fprint",
	 sigscan_test_error_backtrace_fprint );

	SIGSCAN_TEST_RUN(
	 "libsigscan_error_backtrace_sprint",
	 sigscan_test_error_backtrace_sprint );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

