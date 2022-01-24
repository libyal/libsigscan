/*
 * Skip table functions
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
#include <memory.h>
#include <types.h>

#include "libsigscan_libcerror.h"
#include "libsigscan_libcnotify.h"
#include "libsigscan_signature.h"
#include "libsigscan_skip_table.h"

/* Creates a skip table
 * Make sure the value skip_table is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_initialize(
     libsigscan_skip_table_t **skip_table,
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

/* Fills the skip table
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_fill(
     libsigscan_skip_table_t *skip_table,
     libcdata_list_t *signatures_list,
     libcerror_error_t **error )
{
	libcdata_list_element_t *list_element = NULL;
	libsigscan_signature_t *signature     = NULL;
	static char *function                 = "libsigscan_skip_table_fill";
	size_t pattern_index                  = 0;
	size_t skip_value                     = 0;
	uint8_t byte_value                    = 0;

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
	/* First determine the smallest pattern size
	 */
	if( libcdata_list_get_first_element(
	     signatures_list,
	     &list_element,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve first list element.",
		 function );

		return( -1 );
	}
	while( list_element != NULL )
	{
		if( libcdata_list_element_get_value(
		     list_element,
		     (intptr_t **) &signature,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve signature.",
			 function );

			return( -1 );
		}
		if( signature == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: missing signature.",
			 function );

			return( -1 );
		}
		if( ( skip_table->largest_pattern_size == 0 )
		 || ( skip_table->largest_pattern_size < signature->pattern_size ) )
		{
			skip_table->largest_pattern_size = signature->pattern_size;
		}
		if( ( skip_table->smallest_pattern_size == 0 )
		 || ( skip_table->smallest_pattern_size > signature->pattern_size ) )
		{
			skip_table->smallest_pattern_size = signature->pattern_size;
		}
		if( libcdata_list_element_get_next_element(
		     list_element,
		     &list_element,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve next list element.",
			 function );

			return( -1 );
		}
	}
	/* Next fill the skip table
	 */
	if( libcdata_list_get_first_element(
	     signatures_list,
	     &list_element,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve first list element.",
		 function );

		return( -1 );
	}
	while( list_element != NULL )
	{
		if( libcdata_list_element_get_value(
		     list_element,
		     (intptr_t **) &signature,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve signature.",
			 function );

			return( -1 );
		}
		if( signature == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: missing signature.",
			 function );

			return( -1 );
		}
		skip_value = skip_table->smallest_pattern_size;

		for( pattern_index = 0;
		     pattern_index < skip_table->smallest_pattern_size;
		     pattern_index++ )
		{
			skip_value -= 1;
			byte_value  = signature->pattern[ pattern_index ];

			if( ( skip_table->skip_values[ byte_value ] == 0 )
			 || ( skip_value < skip_table->skip_values[ byte_value ] ) )
			{
				skip_table->skip_values[ byte_value ] = skip_value;
			}
		}
		if( libcdata_list_element_get_next_element(
		     list_element,
		     &list_element,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve next list element.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

/* Retrieves the smallest pattern size
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_get_smallest_pattern_size(
     libsigscan_skip_table_t *skip_table,
     size_t *smallest_pattern_size,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_skip_table_get_smallest_pattern_size";

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
	if( smallest_pattern_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid smalles _pattern size.",
		 function );

		return( -1 );
	}
	*smallest_pattern_size = skip_table->smallest_pattern_size;

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
		*skip_value = skip_table->smallest_pattern_size;
	}
	else
	{
		*skip_value = skip_table->skip_values[ byte_value ];
	}
	return( 1 );
}

#if defined( HAVE_DEBUG_OUTPUT )

/* Prints a skip table
 * Returns 1 if successful or -1 on error
 */
int libsigscan_skip_table_printf(
     libsigscan_skip_table_t *skip_table,
     libcerror_error_t **error )
{
	static char *function    = "libsigscan_skip_table_printf";
	int16_t byte_value_index = 0;

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
	libcnotify_printf(
	 "Skip table:\n" );

	for( byte_value_index = 0;
	     byte_value_index < 256;
	     byte_value_index++ )
	{
		if( skip_table->skip_values[ byte_value_index] != 0 )
		{
			libcnotify_printf(
			 "\tByte value: 0x%02" PRIx16 "\t: %" PRIzd "\n",
			 byte_value_index,
			 skip_table->skip_values[ byte_value_index] );
		}
	}
	libcnotify_printf(
	 "\tDefault\t\t: %" PRIzd "\n",
         skip_table->smallest_pattern_size );

	libcnotify_printf(
	 "\n" );

	return( 1 );
}

#endif

