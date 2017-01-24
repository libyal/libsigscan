/*
 * Scan handle
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

#if !defined( _SCAN_HANDLE_H )
#define _SCAN_HANDLE_H

#include <common.h>
#include <file_stream.h>
#include <types.h>

#include "sigscantools_libcerror.h"
#include "sigscantools_libsigscan.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct scan_handle scan_handle_t;

struct scan_handle
{
	/* The libsigscan scanner
	 */
	libsigscan_scanner_t *scanner;

	/* The notification output stream
	 */
	FILE *notify_stream;

	/* Value to indicate if abort was signalled
	 */
	int abort;
};

int scan_handle_initialize(
     scan_handle_t **scan_handle,
     libcerror_error_t **error );

int scan_handle_free(
     scan_handle_t **scan_handle,
     libcerror_error_t **error );

int scan_handle_signal_abort(
     scan_handle_t *scan_handle,
     libcerror_error_t **error );

int scan_handle_copy_string_to_offset(
     const uint8_t *string,
     size_t string_size,
     off64_t *offset,
     libcerror_error_t **error );

int scan_handle_copy_string_to_pattern(
     const uint8_t *string,
     size_t string_size,
     uint8_t **pattern,
     size_t *pattern_size,
     libcerror_error_t **error );

int scan_handle_read_signature_definitions(
     scan_handle_t *scan_handle,
     const system_character_t *filename,
     libcerror_error_t **error );

int scan_handle_scan_input(
     scan_handle_t *scan_handle,
     libsigscan_scan_state_t *scan_state,
     const system_character_t *filename,
     libcerror_error_t **error );

int scan_handle_scan_results_fprint(
     scan_handle_t *scan_handle,
     libsigscan_scan_state_t *scan_state,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _SCAN_HANDLE_H ) */

