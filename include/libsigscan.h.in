/*
 * Library for binary signature scanning
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

#if !defined( _LIBSIGSCAN_H )
#define _LIBSIGSCAN_H

#include <libsigscan/codepage.h>
#include <libsigscan/definitions.h>
#include <libsigscan/error.h>
#include <libsigscan/extern.h>
#include <libsigscan/features.h>
#include <libsigscan/types.h>

#include <stdio.h>

#if defined( LIBSIGSCAN_HAVE_BFIO )
#include <libbfio.h>
#endif

#if defined( __cplusplus )
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Support functions
 * ------------------------------------------------------------------------- */

/* Returns the library version
 */
LIBSIGSCAN_EXTERN \
const char *libsigscan_get_version(
             void );

/* Returns the access flags for reading
 */
LIBSIGSCAN_EXTERN \
int libsigscan_get_access_flags_read(
     void );

/* Retrieves the narrow system string codepage
 * A value of 0 represents no codepage, UTF-8 encoding is used instead
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_get_codepage(
     int *codepage,
     libsigscan_error_t **error );

/* Sets the narrow system string codepage
 * A value of 0 represents no codepage, UTF-8 encoding is used instead
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_set_codepage(
     int codepage,
     libsigscan_error_t **error );

/* -------------------------------------------------------------------------
 * Notify functions
 * ------------------------------------------------------------------------- */

/* Sets the verbose notification
 */
LIBSIGSCAN_EXTERN \
void libsigscan_notify_set_verbose(
      int verbose );

/* Sets the notification stream
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_notify_set_stream(
     FILE *stream,
     libsigscan_error_t **error );

/* Opens the notification stream using a filename
 * The stream is opened in append mode
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_notify_stream_open(
     const char *filename,
     libsigscan_error_t **error );

/* Closes the notification stream if opened using a filename
 * Returns 0 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_notify_stream_close(
     libsigscan_error_t **error );

/* -------------------------------------------------------------------------
 * Error functions
 * ------------------------------------------------------------------------- */

/* Frees an error
 */
LIBSIGSCAN_EXTERN \
void libsigscan_error_free(
      libsigscan_error_t **error );

/* Prints a descriptive string of the error to the stream
 * Returns the number of printed characters if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_error_fprint(
     libsigscan_error_t *error,
     FILE *stream );

/* Prints a descriptive string of the error to the string
 * The end-of-string character is not included in the return value
 * Returns the number of printed characters if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_error_sprint(
     libsigscan_error_t *error,
     char *string,
     size_t size );

/* Prints a backtrace of the error to the stream
 * Returns the number of printed characters if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_error_backtrace_fprint(
     libsigscan_error_t *error,
     FILE *stream );

/* Prints a backtrace of the error to the string
 * The end-of-string character is not included in the return value
 * Returns the number of printed characters if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_error_backtrace_sprint(
     libsigscan_error_t *error,
     char *string,
     size_t size );

/* -------------------------------------------------------------------------
 * Scanner functions
 * ------------------------------------------------------------------------- */

/* Creates a scanner
 * Make sure the value scanner is referencing, is set to NULL
 *
 * Currently only supports "bounded" sigatures (signatures with a fixed offset).
 * Unbounded signatures can be set but will be ignored.
 *
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_initialize(
     libsigscan_scanner_t **scanner,
     libsigscan_error_t **error );

/* Frees a scanner
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_free(
     libsigscan_scanner_t **scanner,
     libsigscan_error_t **error );

/* Signals the scanner to abort its current activity
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_signal_abort(
     libsigscan_scanner_t *scanner,
     libsigscan_error_t **error );

/* Sets the scan buffer size
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_set_scan_buffer_size(
     libsigscan_scanner_t *scanner,
     size_t scan_buffer_size,
     libsigscan_error_t **error );

/* Adds a signature
 * Returns 1 if successful, 0 if signature already exists or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_add_signature(
     libsigscan_scanner_t *scanner,
     const char *identifier,
     size_t identifier_length,
     off64_t pattern_offset,
     const uint8_t *pattern,
     size_t pattern_size,
     uint32_t signature_flags,
     libsigscan_error_t **error );

/* Starts the scan
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_start(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libsigscan_error_t **error );

/* Stops the scan
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_stop(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libsigscan_error_t **error );

/* Scans a buffer
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_buffer(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     const uint8_t *buffer,
     size_t buffer_size,
     libsigscan_error_t **error );

/* Scans a file
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     const char *filename,
     libsigscan_error_t **error );

#if defined( HAVE_WIDE_CHARACTER_TYPE )

/* Scans a file
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file_wide(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     const wchar_t *filename,
     libsigscan_error_t **error );

#endif /* defined( HAVE_WIDE_CHARACTER_TYPE ) */

#if defined( LIBSIGSCAN_HAVE_BFIO )

/* Scans a file using a Basic File IO (bfio) handle
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file_io_handle(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libbfio_handle_t *file_io_handle,
     libsigscan_error_t **error );

#endif /* defined( LIBSIGSCAN_HAVE_BFIO ) */

/* -------------------------------------------------------------------------
 * Scan state functions
 * ------------------------------------------------------------------------- */

/* Creates a scan state
 * Make sure the value scan_state is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scan_state_initialize(
     libsigscan_scan_state_t **scan_state,
     libsigscan_error_t **error );

/* Frees a scan state
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scan_state_free(
     libsigscan_scan_state_t **scan_state,
     libsigscan_error_t **error );

/* Sets the data size
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scan_state_set_data_size(
     libsigscan_scan_state_t *scan_state,
     size64_t data_size,
     libsigscan_error_t **error );

/* Retrieves the number of scan results
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scan_state_get_number_of_results(
     libsigscan_scan_state_t *scan_state,
     int *number_of_results,
     libsigscan_error_t **error );

/* Retrieves a specific scan result
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scan_state_get_result(
     libsigscan_scan_state_t *scan_state,
     int result_index,
     libsigscan_scan_result_t **scan_result,
     libsigscan_error_t **error );

/* -------------------------------------------------------------------------
 * Scan result functions
 * ------------------------------------------------------------------------- */

/* Frees a scan result
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scan_result_free(
     libsigscan_scan_result_t **scan_result,
     libsigscan_error_t **error );

/* Retrieves the size of the identifier
 * The returned size includes the end of string character
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scan_result_get_identifier_size(
     libsigscan_scan_result_t *scan_result,
     size_t *identifier_size,
     libsigscan_error_t **error );

/* Retrieves the identifier
 * The size should include the end of string character
 * Returns 1 if successful or -1 on error
 */
LIBSIGSCAN_EXTERN \
int libsigscan_scan_result_get_identifier(
     libsigscan_scan_result_t *scan_result,
     char *identifier,
     size_t identifier_size,
     libsigscan_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_H ) */

