/*
 * Signature definitions
 *
 * Copyright (C) 2014-2015, Joachim Metz <joachim.metz@gmail.com>
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
#include <memory.h>
#include <types.h>

#include "signature_definitions.h"
#include "sigscantools_libcdata.h"
#include "sigscantools_libcerror.h"
#include "sigscantools_libcfile.h"
#include "sigscantools_libsigscan.h"

#define SIGNATURE_DEFINITIONS_BUFFER_SIZE		16 * 1024 * 1024

/* Creates signature definitions
 * Make sure the value signature_definitions is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int signature_definitions_initialize(
     signature_definitions_t **signature_definitions,
     libcerror_error_t **error )
{
	static char *function = "signature_definitions_initialize";

	if( signature_definitions == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature definitions.",
		 function );

		return( -1 );
	}
	if( *signature_definitions != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid signature definitions value already set.",
		 function );

		return( -1 );
	}
	*signature_definitions = memory_allocate_structure(
	                          signature_definitions_t );

	if( *signature_definitions == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create signature definitions.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *signature_definitions,
	     0,
	     sizeof( signature_definitions_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear signature definitions.",
		 function );

		memory_free(
		 *signature_definitions );

		*signature_definitions = NULL;

		return( -1 );
	}
	if( libcdata_array_initialize(
	     &( ( *signature_definitions )->signatures_array ),
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create signatures array.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *signature_definitions != NULL )
	{
		memory_free(
		 *signature_definitions );

		*signature_definitions = NULL;
	}
	return( -1 );
}

/* Frees signature definitions
 * Returns 1 if successful or -1 on error
 */
int signature_definitions_free(
     signature_definitions_t **signature_definitions,
     libcerror_error_t **error )
{
	static char *function = "signature_definitions_free";
	int result            = 1;

	if( signature_definitions == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature definitions.",
		 function );

		return( -1 );
	}
	if( *signature_definitions != NULL )
	{
		if( libcdata_array_free(
		     &( ( *signature_definitions )->signatures_array ),
		     (int (*)(intptr_t **, libcerror_error_t **)) NULL,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free signatures array.",
			 function );

			result = -1;
		}
		memory_free(
		 *signature_definitions );

		*signature_definitions = NULL;
	}
	return( result );
}

/* Read the signature definitions from file
 * Returns 1 if successful or -1 on error
 */
int signature_definitions_read(
     signature_definitions_t *signature_definitions,
     const libcstring_system_character_t *filename,
     libcerror_error_t **error )
{
	libcfile_file_t *file = NULL;
	uint8_t *buffer       = NULL;
	static char *function = "signature_definitions_read";
	size_t buffer_offset  = 0;
	size_t read_size      = 0;
	ssize_t read_count    = 0;

	if( signature_definitions == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature definitions.",
		 function );

		return( -1 );
	}
	buffer = (uint8_t *) memory_allocate(
	                      sizeof( uint8_t ) * SIGNATURE_DEFINITIONS_BUFFER_SIZE );

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
#if defined( LIBCSTRING_HAVE_WIDE_SYSTEM_CHARACTER )
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
		read_size = SIGNATURE_DEFINITIONS_BUFFER_SIZE - buffer_offset;

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
/* TODO read lines */
		read_size = SIGNATURE_DEFINITIONS_BUFFER_SIZE - buffer_offset;

		if( buffer_offset >= SIGNATURE_DEFINITIONS_BUFFER_SIZE )
		{
			buffer_offset = 0;
		}
		else
		{
			if( memory_copy(
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
	     error ) != 1 )
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

