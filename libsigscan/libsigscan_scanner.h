/*
 * Scanner functions
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

#if !defined( _LIBSIGSCAN_INTERNAL_SCANNER_H )
#define _LIBSIGSCAN_INTERNAL_SCANNER_H

#include <common.h>
#include <types.h>

#include "libsigscan_extern.h"
#include "libsigscan_libbfio.h"
#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_scan_tree.h"
#include "libsigscan_types.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_internal_scanner libsigscan_internal_scanner_t;

struct libsigscan_internal_scanner
{
	/* The (scan) buffer size
	 */
	size_t buffer_size;

	/* The signatures list
	 */
	libcdata_list_t *signatures_list;

	/* The header (offset relative from start) scan tree
	 */
	libsigscan_scan_tree_t *header_scan_tree;

	/* The footer (offset relative from start) scan tree
	 */
	libsigscan_scan_tree_t *footer_scan_tree;

	/* The (unbounded) scan tree
	 */
	libsigscan_scan_tree_t *scan_tree;

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
int libsigscan_scanner_set_scan_buffer_size(
     libsigscan_scanner_t *scanner,
     size_t scan_buffer_size,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_add_signature(
     libsigscan_scanner_t *scanner,
     const char *identifier,
     size_t identifier_length,
     off64_t pattern_offset,
     const uint8_t *pattern,
     size_t pattern_size,
     uint32_t signature_flags,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_start(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_stop(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_buffer(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     const uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error );

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     const char *filename,
     libcerror_error_t **error );

#if defined( HAVE_WIDE_CHARACTER_TYPE )

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file_wide(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     const wchar_t *filename,
     libcerror_error_t **error );

#endif /* defined( HAVE_WIDE_CHARACTER_TYPE ) */

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file_io_handle(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libbfio_handle_t *file_io_handle,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_INTERNAL_SCANNER_H ) */

