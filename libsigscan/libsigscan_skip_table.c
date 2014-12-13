/*
 * Skip table functions
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

#include <common.h>
#include <memory.h>
#include <types.h>

#include "libsigscan_libcerror.h"
#include "libsigscan_skip_table.h"

/* Creates a skip table
 * Make sure the value skip_table is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_initialize(
     libsigscan_skip_table_t **skip_table,
     size_t skip_pattern_size,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_skip_table_initialize";

	if( skip_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid skip table.",
		 function );

		return( -1 );
	}
	if( *skip_table != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid skip table value already set.",
		 function );

		return( -1 );
	}
	if( skip_pattern_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid skip pattern size value out of bounds.",
		 function );

		return( -1 );
	}
	*skip_table = memory_allocate_structure(
	               libsigscan_skip_table_t );

	if( *skip_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create skip table.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *skip_table,
	     0,
	     sizeof( libsigscan_skip_table_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear skip table.",
		 function );

		memory_free(
		 *skip_table );

		*skip_table = NULL;

		return( -1 );
	}
	( *skip_table )->skip_pattern_size = skip_pattern_size;

	return( 1 );

on_error:
	if( *skip_table != NULL )
	{
		memory_free(
		 *skip_table );

		*skip_table = NULL;
	}
	return( -1 );
}

/* Frees a skip table
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_free(
     libsigscan_skip_table_t **skip_table,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_skip_table_free";

	if( skip_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid skip table.",
		 function );

		return( -1 );
	}
	if( *skip_table != NULL )
	{
		memory_free(
		 *skip_table );

		*skip_table = NULL;
	}
	return( 1 );
}

/* Builds the skip table
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_build(
     libsigscan_skip_table_t *skip_table,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_skip_table_build";

	if( skip_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid skip table.",
		 function );

		return( -1 );
	}
/* TODO iterate over the patterns and fill the skip table */
	return( 1 );
}

/* Retrieves a specific skip value
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_get_skip_value(
     libsigscan_skip_table_t *skip_table,
     uint8_t byte_value,
     size_t *skip_value,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_skip_table_get_skip_value";

	if( skip_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid skip table.",
		 function );

		return( -1 );
	}
	if( skip_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid skip value.",
		 function );

		return( -1 );
	}
	if( skip_table->skip_values[ byte_value ] == 0 )
	{
		*skip_value = skip_table->skip_pattern_size;
	}
	else
	{
		*skip_value = skip_table->skip_values[ byte_value ];
	}
	return( 1 );
}

/* Sets a specific skip value
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_set_skip_value(
     libsigscan_skip_table_t *skip_table,
     uint8_t byte_value,
     size_t skip_value,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_skip_table_set_skip_value";

	if( skip_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid skip table.",
		 function );

		return( -1 );
	}
	if( skip_value > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid skip value value out of bounds.",
		 function );

		return( -1 );
	}
	if( skip_value > (size_t) skip_table->skip_pattern_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid skip value value out of bounds.",
		 function );

		return( -1 );
	}
	if( ( skip_table->skip_values[ byte_value ] == 0 )
	 || ( skip_value < skip_table->skip_values[ byte_value ] ) )
	{
		skip_table->skip_values[ byte_value ] = skip_value;
	}
	return( 1 );
}

