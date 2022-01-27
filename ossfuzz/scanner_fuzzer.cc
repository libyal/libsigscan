/*
 * OSS-Fuzz target for libsigscan scanner type
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

#include <stddef.h>
#include <stdint.h>

/* Note that some of the OSS-Fuzz engines use C++
 */
extern "C" {

#include "ossfuzz_libsigscan.h"

int LLVMFuzzerTestOneInput(
     const uint8_t *data,
     size_t size )
{
	libsigscan_scan_state_t *scan_state = NULL;
	libsigscan_scanner_t *scanner       = NULL;

	if( libsigscan_scanner_initialize(
	     &scanner,
	     NULL ) != 1 )
	{
		return( 0 );
	}
	if( libsigscan_scanner_add_signature(
	     scanner,
	     "test1",
	     5,
	     13,
	     (uint8_t *) "FuZzInG",
	     7,
	     LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START,
	     NULL ) != 1 )
	{
		goto on_error_libsigscan;
	}
	if( libsigscan_scanner_add_signature(
	     scanner,
	     "test2",
	     5,
	     -13,
	     (uint8_t *) "OsSFuZz",
	     7,
	     LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_END,
	     NULL ) != 1 )
	{
		goto on_error_libsigscan;
	}
	if( libsigscan_scan_state_initialize(
	     &scan_state,
	     NULL ) != 1 )
	{
		goto on_error_libsigscan;
	}
	libsigscan_scanner_scan_buffer(
	 scanner,
	 scan_state,
	 data,
	 size,
	 NULL );

	libsigscan_scan_state_free(
	 &scan_state,
	 NULL );

on_error_libsigscan:
	libsigscan_scanner_free(
	 &scanner,
	 NULL );

	return( 0 );
}

} /* extern "C" */

