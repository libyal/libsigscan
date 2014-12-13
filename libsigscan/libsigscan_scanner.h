/*
 * Scanner functions
 *
 * Copyright (c) 2014, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _LIBSIGSCAN_INTERNAL_SCANNER_H )
#define _LIBSIGSCAN_INTERNAL_SCANNER_H

#include <common.h>
#include <types.h>

#include "libsigscan_extern.h"
#include "libsigscan_libbfio.h"
#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_types.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_internal_scanner libsigscan_internal_scanner_t;

struct libsigscan_internal_scanner
{
	/* The signatures array
	 */
	libcdata_array_t *signatures_array;

	/* Value to indicate if the scan tree was initialized
	 */
	int scan_tree_initialized;

	/* Value to indicate if abort was signalled
	 */
	int abort;
};

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_initialize(
     libsigscan_scanner_t **scanner,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_free(
     libsigscan_scanner_t **scanner,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_signal_abort(
     libsigscan_scanner_t *scanner,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_add_signature(
     libsigscan_scanner_t *scanner,
     const char *identifier,
     size_t identifier_size,
     off64_t offset,
     const uint8_t *pattern,
     size_t pattern_size,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_start_scan(
     libsigscan_scanner_t *scanner,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_stop_scan(
     libsigscan_scanner_t *scanner,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_buffer(
     libsigscan_scanner_t *scanner,
     const uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file(
     libsigscan_scanner_t *scanner,
     const char *filename,
     libcerror_error_t **error );

#if defined( HAVE_WIDE_CHARACTER_TYPE )

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file_wide(
     libsigscan_scanner_t *scanner,
     const wchar_t *filename,
     libcerror_error_t **error );

#endif /* defined( HAVE_WIDE_CHARACTER_TYPE ) */

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file_io_handle(
     libsigscan_scanner_t *scanner,
     libbfio_handle_t *file_io_handle,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_get_number_of_scan_results(
     libsigscan_scanner_t *scanner,
     int *number_of_scan_results,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_get_scan_result(
     libsigscan_scanner_t *scanner,
     int scan_result_index,
     libsigscan_scan_result_t **scan_result,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif

