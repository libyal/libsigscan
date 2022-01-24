/*
 * Scan handle
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

#include <common.h>
#include <file_stream.h>
#include <memory.h>
#include <types.h>

#include "scan_handle.h"
#include "sigscantools_libcerror.h"
#include "sigscantools_libcfile.h"
#include "sigscantools_libsigscan.h"

#define SCAN_HANDLE_BUFFER_SIZE			16 * 1024 * 1024
#define SCAN_HANDLE_NOTIFY_STREAM		stdout

/* Creates a scan handle
 * Make sure the value scan_handle is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int scan_handle_initialize(
     scan_handle_t **scan_handle,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_initialize";

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan handle.",
		 function );

		return( -1 );
	}
	if( *scan_handle != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan handle value already set.",
		 function );

		return( -1 );
	}
	*scan_handle = memory_allocate_structure(
	                scan_handle_t );

	if( *scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan handle.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *scan_handle,
	     0,
	     sizeof( scan_handle_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear scan handle.",
		 function );

		memory_free(
		 *scan_handle );

		*scan_handle = NULL;

		return( -1 );
	}
	if( libsigscan_scanner_initialize(
	     &( ( *scan_handle )->scanner ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize scanner.",
		 function );

		goto on_error;
	}
	( *scan_handle )->notify_stream = SCAN_HANDLE_NOTIFY_STREAM;

	return( 1 );

on_error:
	if( *scan_handle != NULL )
	{
		memory_free(
		 *scan_handle );

		*scan_handle = NULL;
	}
	return( -1 );
}

/* Frees a scan handle
 * Returns 1 if successful or -1 on error
 */
int scan_handle_free(
     scan_handle_t **scan_handle,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_free";
	int result            = 1;

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan handle.",
		 function );

		return( -1 );
	}
	if( *scan_handle != NULL )
	{
		if( ( *scan_handle )->scanner != NULL )
		{
			if( libsigscan_scanner_free(
			     &( ( *scan_handle )->scanner ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free scanner.",
				 function );

				result = -1;
			}
		}
		memory_free(
		 *scan_handle );

		*scan_handle = NULL;
	}
	return( result );
}

/* Signals the scan handle to abort
 * Returns 1 if successful or -1 on error
 */
int scan_handle_signal_abort(
     scan_handle_t *scan_handle,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_signal_abort";

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan handle.",
		 function );

		return( -1 );
	}
	scan_handle->abort = 1;

	if( scan_handle->scanner != NULL )
	{
		if( libsigscan_scanner_signal_abort(
		     scan_handle->scanner,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to signal scanner to abort.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

/* Copies the string to an offset
 * Returns 1 if successful or -1 on error
 */
int scan_handle_copy_string_to_offset(
     const uint8_t *string,
     size_t string_size,
     off64_t *offset,
     libcerror_error_t **error )
{
	static char *function        = "scan_handle_copy_string_to_offset";
	size_t string_index          = 0;
	uint8_t byte_value           = 0;
	uint8_t maximum_string_index = 20;
	int8_t sign                  = 1;

	if( string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string.",
		 function );

		return( -1 );
	}
	if( string_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid string size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset.",
		 function );

		return( -1 );
	}
	*offset = 0;

	if( string[ string_index ] == '-' )
	{
		string_index++;
		maximum_string_index++;

		sign = -1;
	}
	else if( string[ string_index ] == '+' )
	{
		string_index++;
		maximum_string_index++;
	}
	while( string_index < string_size )
	{
		if( string[ string_index ] == 0 )
		{
			break;
		}
		if( string_index > (size_t) maximum_string_index )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_LARGE,
			 "%s: string too large.",
			 function );

			return( -1 );
		}
		*offset *= 10;

		if( ( string[ string_index ] >= '0' )
		 && ( string[ string_index ] <= '9' ) )
		{
			byte_value = string[ string_index ] - '0';
		}
		else
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
			 "%s: unsupported character value: %" PRIc_SYSTEM " at index: %d.",
			 function,
			 string[ string_index ],
			 string_index );

			return( -1 );
		}
		*offset += byte_value;

		string_index++;
	}
	if( sign == -1 )
	{
		*offset *= (off64_t) -1;
	}
	return( 1 );
}

/* Copies the string to a pattern
 * Returns 1 if successful or -1 on error
 */
int scan_handle_copy_string_to_pattern(
     const uint8_t *string,
     size_t string_size,
     uint8_t **pattern,
     size_t *pattern_size,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_copy_string_to_pattern";
	size_t pattern_index  = 0;
	size_t string_index   = 0;
	uint8_t byte_value    = 0;

	if( string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string.",
		 function );

		return( -1 );
	}
	if( pattern == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern.",
		 function );

		return( -1 );
	}
	if( *pattern != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid pattern value already set.",
		 function );

		return( -1 );
	}
	if( pattern_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern size.",
		 function );

		return( -1 );
	}
	*pattern = (uint8_t *) memory_allocate(
	                        sizeof( uint8_t ) * string_size );

	if( *pattern == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create pattern.",
		 function );

		 goto on_error;
	}
	while( string_index < ( string_size - 1 ) )
	{
		( *pattern )[ pattern_index ] = string[ string_index++ ];

		if( ( *pattern )[ pattern_index ] == '\\' )
		{
			switch( string[ string_index ] )
			{
				case '\\':
					( *pattern )[ pattern_index ] = '\\';
					break;

				case 'a':
					( *pattern )[ pattern_index ] = '\a';
					break;

				case 'b':
					( *pattern )[ pattern_index ] = '\b';
					break;

				case 'f':
					( *pattern )[ pattern_index ] = '\f';
					break;

				case 'n':
					( *pattern )[ pattern_index ] = '\n';
					break;

				case 'r':
					( *pattern )[ pattern_index ] = '\r';
					break;

				case 't':
					( *pattern )[ pattern_index ] = '\t';
					break;

				case 'v':
					( *pattern )[ pattern_index ] = '\v';
					break;

				/* Hexadecimal values are treated in one place using strtoul()
				 */
				case 'x':
					if( ( string_index + 2 ) >= string_size )
					{
						libcerror_error_set(
						 error,
						 LIBCERROR_ERROR_DOMAIN_RUNTIME,
						 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
						 "%s: invalid string index value out of bounds.",
						 function );

						goto on_error;
					}
					if( ( string[ string_index + 1 ] >= '0' )
					 && ( string[ string_index + 1 ] <= '9' ) )
					{
						byte_value = string[ string_index + 1 ] - '0';
					}
					else if( ( string[ string_index + 1 ] >= 'A' )
					      && ( string[ string_index + 1 ] <= 'F' ) )
					{
						byte_value = string[ string_index + 1 ] - 'A' + 10;
					}
					else if( ( string[ string_index + 1 ] >= 'a' )
					      && ( string[ string_index + 1 ] <= 'f' ) )
					{
						byte_value = string[ string_index + 1 ] - 'a' + 10;
					}
					else
					{
						break;
					}
					byte_value <<= 4;

					if( ( string[ string_index + 2 ] >= '0' )
					 && ( string[ string_index + 2 ] <= '9' ) )
					{
						byte_value |= string[ string_index + 2 ] - '0';
					}
					else if( ( string[ string_index + 2 ] >= 'A' )
					      && ( string[ string_index + 2 ] <= 'F' ) )
					{
						byte_value |= string[ string_index + 2 ] - 'A' + 10;
					}
					else if( ( string[ string_index + 2 ] >= 'a' )
					      && ( string[ string_index + 2 ] <= 'f' ) )
					{
						byte_value |= string[ string_index + 2 ] - 'a' + 10;
					}
					else
					{
						break;
					}
					( *pattern )[ pattern_index ] = byte_value;

					string_index += 2;

					break;

				default:
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: invalid string value out of bounds.",
					 function );

					goto on_error;
			}
			string_index++;
		}
		pattern_index++;
	}
	*pattern_size = pattern_index;

	return( 1 );

on_error:
	if( *pattern != NULL )
	{
		memory_free(
		 *pattern );

		*pattern = NULL;
	}
	return( -1 );
}

/* Read the signature definitions from file
 * Returns 1 if successful or -1 on error
 */
int scan_handle_read_signature_definitions(
     scan_handle_t *scan_handle,
     const system_character_t *filename,
     libcerror_error_t **error )
{
	libcfile_file_t *file             = NULL;
	uint8_t *buffer                   = NULL;
	uint8_t *identifier               = NULL;
	uint8_t *pattern                  = NULL;
	uint8_t *pattern_offset_string    = NULL;
	uint8_t *pattern_string           = NULL;
	static char *function             = "scan_handle_read_signature_definitions";
	off64_t pattern_offset            = 0;
	size_t buffer_offset              = 0;
	size_t identifier_size            = 0;
	size_t line_offset                = 0;
	size_t pattern_offset_string_size = 0;
	size_t pattern_size               = 0;
	size_t pattern_string_size        = 0;
	size_t read_size                  = 0;
	ssize_t read_count                = 0;
	uint32_t signature_flags          = 0;

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan handle.",
		 function );

		return( -1 );
	}
	buffer = (uint8_t *) memory_allocate(
	                      sizeof( uint8_t ) * SCAN_HANDLE_BUFFER_SIZE );

	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create buffer.",
		 function );

		 goto on_error;
	}
	if( libcfile_file_initialize(
	     &file,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize file.",
		 function );

		goto on_error;
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	if( libcfile_file_open_wide(
	     file,
	     filename,
	     LIBCFILE_OPEN_READ,
	     error ) != 1 )
#else
	if( libcfile_file_open(
	     file,
	     filename,
	     LIBCFILE_OPEN_READ,
	     error ) != 1 )
#endif
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to open file.",
		 function );

		goto on_error;
	}
	do
	{
		read_size = SCAN_HANDLE_BUFFER_SIZE - buffer_offset;

		read_count = libcfile_file_read_buffer(
		              file,
		              &( buffer[ buffer_offset ] ),
		              read_size,
		              error );

		if( read_count < 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read buffer from file.",
			 function );

			goto on_error;
		}
		read_size   = read_count + buffer_offset;
		line_offset = 0;

		for( buffer_offset = 0;
		     buffer_offset < ( read_size - 1 );
		     buffer_offset++ )
		{
			if( ( buffer_offset < ( read_size - 1 ) )
			 && ( buffer[ buffer_offset ] != '\n' ) )
			{
				continue;
			}
			if( line_offset >= read_size )
			{
				break;
			}
			/* Ignore lines of comment and empty lines
			 */
			if( ( buffer[ line_offset ] == '\n' )
			 || ( buffer[ line_offset ] == '\r' )
			 || ( buffer[ line_offset ] == '#' ) )
			{
				line_offset = buffer_offset + 1;

				continue;
			}
			identifier      = &( buffer[ line_offset ] );
			identifier_size = line_offset;

			/* The identifier should be formatted as [a-zA-Z0-9_]+
			 */
			while( ( ( buffer[ line_offset ] >= 'a' )
			     &&  ( buffer[ line_offset ] <= 'i' ) )
			    || ( ( buffer[ line_offset ] >= 'j' )
			     &&  ( buffer[ line_offset ] <= 'r' ) )
			    || ( ( buffer[ line_offset ] >= 's' )
			     &&  ( buffer[ line_offset ] <= 'z' ) )
			    || ( ( buffer[ line_offset ] >= 'A' )
			     &&  ( buffer[ line_offset ] <= 'I' ) )
			    || ( ( buffer[ line_offset ] >= 'J' )
			     &&  ( buffer[ line_offset ] <= 'R' ) )
			    || ( ( buffer[ line_offset ] >= 'S' )
			     &&  ( buffer[ line_offset ] <= 'Z' ) )
			    || ( ( buffer[ line_offset ] >= '0' )
			     &&  ( buffer[ line_offset ] <= '9' ) )
			    || ( buffer[ line_offset ] == '_' ) )
			{
				line_offset += 1;

				if( line_offset > buffer_offset )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: unable to parse identifier.",
					 function );

					goto on_error;
				}
			}
			identifier_size = line_offset - identifier_size + 1;

			while( ( buffer[ line_offset ] == ' ' )
			    || ( buffer[ line_offset ] == '\t' ) )
			{
				line_offset += 1;

				if( line_offset > buffer_offset )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: unable to parse identifier and offset separator.",
					 function );

					goto on_error;
				}
			}
			pattern_offset_string      = &( buffer[ line_offset ] );
			pattern_offset_string_size = line_offset;

			if( ( buffer[ line_offset ] == '-' )
			 || ( buffer[ line_offset ] == '+' ) )
			{
				line_offset += 1;

				if( line_offset > buffer_offset )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: unable to parse identifier.",
					 function );

					goto on_error;
				}
			}
			/* The offset should be formatted as [-+]?[0-9]+
			 */
			while( ( buffer[ line_offset ] >= '0' )
			    && ( buffer[ line_offset ] <= '9' ) )
			{
				line_offset += 1;

				if( line_offset > buffer_offset )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: unable to parse offset.",
					 function );

					goto on_error;
				}
			}
			pattern_offset_string_size = line_offset - pattern_offset_string_size + 1;

			while( ( buffer[ line_offset ] == ' ' )
			    || ( buffer[ line_offset ] == '\t' ) )
			{
				line_offset += 1;

				if( line_offset > buffer_offset )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: unable to parse offset and pattern separator.",
					 function );

					goto on_error;
				}
			}
			pattern_string      = &( buffer[ line_offset ] );
			pattern_string_size = line_offset;

			/* The pattern should be formatted as [^ \n\r\t]+
			 */
			while( ( buffer[ line_offset ] != ' ' )
			    && ( buffer[ line_offset ] != '\n' )
			    && ( buffer[ line_offset ] != '\r' )
			    && ( buffer[ line_offset ] != '\t' ) )
			{
				line_offset += 1;

				if( line_offset > buffer_offset )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: unable to parse pattern.",
					 function );

					goto on_error;
				}
			}
			pattern_string_size = line_offset - pattern_string_size + 1;

/* TODO ignore trailing whitespace */

/* TODO check for trailing data */

			identifier[ identifier_size - 1 ]                       = 0;
			pattern_offset_string[ pattern_offset_string_size - 1 ] = 0;
			pattern_string[ pattern_string_size - 1 ]               = 0;

			if( scan_handle_copy_string_to_offset(
			     pattern_offset_string,
			     pattern_offset_string_size,
			     &pattern_offset,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
				 "%s: unable to copy string to offset.",
				 function );

				goto on_error;
			}
			if( scan_handle_copy_string_to_pattern(
			     pattern_string,
			     pattern_string_size,
			     &pattern,
			     &pattern_size,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
				 "%s: unable to copy string to pattern.",
				 function );

				goto on_error;
			}
			if( pattern_offset < 0 )
			{
				signature_flags = LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_END;
				pattern_offset *= -1;
			}
			else
			{
				signature_flags = LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START;
			}
			if( libsigscan_scanner_add_signature(
			     scan_handle->scanner,
			     (char *) identifier,
			     identifier_size,
			     pattern_offset,
			     pattern,
			     pattern_size,
			     signature_flags,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
				 "%s: unable to append signature: %s.",
				 function,
				 (char *) identifier );

				goto on_error;
			}
			memory_free(
			 pattern );

			pattern = NULL;

			line_offset = buffer_offset + 1;
		}
		read_size = SCAN_HANDLE_BUFFER_SIZE - buffer_offset;

		if( buffer_offset >= SCAN_HANDLE_BUFFER_SIZE )
		{
			buffer_offset = 0;
		}
		else
		{
			if( memmove(
			     buffer,
			     &( buffer[ buffer_offset ] ),
			     read_size ) == NULL )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
				 "%s: unable to copy remaining data in buffer.",
				 function );

				goto on_error;
			}
			buffer_offset = read_size;
		}
	}
	while( read_count != 0 );

	if( libcfile_file_close(
	     file,
	     error ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_CLOSE_FAILED,
		 "%s: unable to close file.",
		 function );

		goto on_error;
	}
	if( libcfile_file_free(
	     &file,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free file.",
		 function );

		goto on_error;
	}
	memory_free(
	 buffer );

	return( 1 );

on_error:
	if( pattern != NULL )
	{
		memory_free(
		 pattern );
	}
	if( file != NULL )
	{
		libcfile_file_free(
		 &file,
		 NULL );
	}
	if( buffer != NULL )
	{
		memory_free(
		 buffer );
	}
	return( -1 );
}

/* Scans the input
 * Returns 1 if successful or -1 on error
 */
int scan_handle_scan_input(
     scan_handle_t *scan_handle,
     libsigscan_scan_state_t *scan_state,
     const system_character_t *filename,
     libcerror_error_t **error )
{
	static char *function = "scan_handle_scan_input";

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan handle.",
		 function );

		return( -1 );
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	if( libsigscan_scanner_scan_file_wide(
	     scan_handle->scanner,
	     scan_state,
	     filename,
	     error ) != 1 )
#else
	if( libsigscan_scanner_scan_file(
	     scan_handle->scanner,
	     scan_state,
	     filename,
	     error ) != 1 )
#endif
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to scan file.",
		 function );

		return( -1 );
	}
	if( scan_handle_scan_results_fprint(
	     scan_handle,
	     scan_state,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_PRINT_FAILED,
		 "%s: unable to print scan results.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Prints the scan results
 * Returns 1 if successful or -1 on error
 */
int scan_handle_scan_results_fprint(
     scan_handle_t *scan_handle,
     libsigscan_scan_state_t *scan_state,
     libcerror_error_t **error )
{
	libsigscan_scan_result_t *scan_result = NULL;
	static char *function                 = "scan_handle_scan_results_fprint";
	char *identifier                      = NULL;
	size_t identifier_size                = 0;
	int number_of_results                 = 0;
	int result_index                      = 0;

	if( scan_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan handle.",
		 function );

		return( -1 );
	}
	if( libsigscan_scan_state_get_number_of_results(
	     scan_state,
	     &number_of_results,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of scan results.",
		 function );

		goto on_error;
	}
	fprintf(
	 scan_handle->notify_stream,
	 "Signature scanner:\n" );

	fprintf(
	 scan_handle->notify_stream,
	 "\tNumber of scan results\t: %d\n",
	 number_of_results );

	fprintf(
	 scan_handle->notify_stream,
	 "\n" );

	if( number_of_results > 0 )
	{
		for( result_index = 0;
		     result_index < number_of_results;
		     result_index++ )
		{
			fprintf(
			 scan_handle->notify_stream,
			 "Scan result: %d\n",
			 result_index + 1 );

			if( libsigscan_scan_state_get_result(
			     scan_state,
			     result_index,
			     &scan_result,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve scan result: %d.",
				 function,
				 result_index + 1 );

				goto on_error;
			}
			if( libsigscan_scan_result_get_identifier_size(
			     scan_result,
			     &identifier_size,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve scan result: %d identifier size.",
				 function,
				 result_index + 1 );

				goto on_error;
			}
			fprintf(
			 scan_handle->notify_stream,
			 "\tIdentifier\t\t:" );

			if( identifier_size > 0 )
			{
				identifier = (char *) memory_allocate(
				                       sizeof( char ) * identifier_size );

				if( identifier == NULL )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_MEMORY,
					 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
					 "%s: unable to create scan handle.",
					 function );

					 goto on_error;
				}
				if( libsigscan_scan_result_get_identifier(
				     scan_result,
				     identifier,
				     identifier_size,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
					 "%s: unable to retrieve scan result: %d identifier.",
					 function,
					 result_index + 1 );

					goto on_error;
				}
				fprintf(
				 scan_handle->notify_stream,
				 " %s",
				 identifier );

				memory_free(
				 identifier );

				identifier = NULL;
			}
			fprintf(
			 scan_handle->notify_stream,
			 "\n" );

			if( libsigscan_scan_result_free(
			     &scan_result,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free scan result.",
				 function );

				goto on_error;
			}
			fprintf(
			 scan_handle->notify_stream,
			 "\n" );
		}
	}
	return( 1 );

on_error:
	if( identifier != NULL )
	{
		memory_free(
		 identifier );
	}
	if( scan_result != NULL )
	{
		libsigscan_scan_result_free(
		 &scan_result,
		 NULL );
	}
	return( -1 );
}

