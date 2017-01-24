/*
 * Signature table functions
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
#include <memory.h>
#include <types.h>

#include "libsigscan_byte_value_group.h"
#include "libsigscan_definitions.h"
#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_libcnotify.h"
#include "libsigscan_offsets_list.h"
#include "libsigscan_signature.h"
#include "libsigscan_signature_table.h"

/* Creates a signature table
 * Make sure the value signature_table is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_table_initialize(
     libsigscan_signature_table_t **signature_table,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_table_initialize";

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	if( *signature_table != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid signature table value already set.",
		 function );

		return( -1 );
	}
	*signature_table = memory_allocate_structure(
	                    libsigscan_signature_table_t );

	if( *signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create signature table.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *signature_table,
	     0,
	     sizeof( libsigscan_signature_table_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear signature table.",
		 function );

		memory_free(
		 *signature_table );

		*signature_table = NULL;

		return( -1 );
	}
	if( libcdata_list_initialize(
	     &( ( *signature_table )->byte_value_groups_list ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create byte values groups list.",
		 function );

		goto on_error;
	}
	if( libcdata_list_initialize(
	     &( ( *signature_table )->signatures_list ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create signatures list.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *signature_table != NULL )
	{
		if( ( *signature_table )->byte_value_groups_list != NULL )
		{
			libcdata_list_free(
			 &( ( *signature_table )->byte_value_groups_list ),
			 NULL,
			 NULL );
		}
		memory_free(
		 *signature_table );

		*signature_table = NULL;
	}
	return( -1 );
}

/* Frees a signature table
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_table_free(
     libsigscan_signature_table_t **signature_table,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_table_free";
	int result            = 1;

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	if( *signature_table != NULL )
	{
		if( libcdata_list_free(
		     &( ( *signature_table )->byte_value_groups_list ),
		     (int (*)(intptr_t **,libcerror_error_t **)) &libsigscan_byte_value_group_free,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free byte value groups list.",
			 function );

			result = -1;
		}
		/* The signatures in the list are references and freed elsewhere
		 */
		if( libcdata_list_free(
		     &( ( *signature_table )->signatures_list ),
		     NULL,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free signatures list.",
			 function );

			result = -1;
		}
		memory_free(
		 *signature_table );

		*signature_table = NULL;
	}
	return( result );
}

/* Fills the signature table
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_table_fill(
     libsigscan_signature_table_t *signature_table,
     libcdata_list_t *signatures_list,
     libcdata_list_t *offsets_ignore_list,
     int pattern_offsets_mode,
     uint64_t pattern_offsets_range_size,
     libcerror_error_t **error )
{
	libcdata_list_element_t *list_element = NULL;
	libsigscan_signature_t *signature     = NULL;
	static char *function                 = "libsigscan_signature_table_fill";
	off64_t pattern_offset                = 0;
	size_t pattern_index                  = 0;
	int add_signature                     = 0;
	int result                            = 0;

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	if( ( pattern_offsets_mode != LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START )
	 && ( pattern_offsets_mode != LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_END )
	 && ( pattern_offsets_mode != LIBSIGSCAN_PATTERN_OFFSET_MODE_UNBOUND ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported pattern offsets mode.",
		 function );

		return( -1 );
	}
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
		switch( pattern_offsets_mode )
		{
			case LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START:
				if( ( signature->signature_flags & LIBSIGSCAN_SIGNATURE_FLAGS_MASK ) == LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_START )
				{
					add_signature = 1;
				}
				else
				{
					add_signature = 0;
				}
				break;

			case LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_END:
				if( ( signature->signature_flags & LIBSIGSCAN_SIGNATURE_FLAGS_MASK ) == LIBSIGSCAN_SIGNATURE_FLAG_OFFSET_RELATIVE_FROM_END )
				{
					add_signature = 1;
				}
				else
				{
					add_signature = 0;
				}
				break;

			case LIBSIGSCAN_PATTERN_OFFSET_MODE_UNBOUND:
				add_signature = 1;
				break;

			default:
				add_signature = 0;
				break;
		}
		if( add_signature != 0 )
		{
			if( pattern_offsets_mode == LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START )
			{
				pattern_offset = signature->pattern_offset;
			}
			else if( pattern_offsets_mode == LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_END )
			{
				pattern_offset = pattern_offsets_range_size - signature->pattern_offset;
			}
			else if( pattern_offsets_mode == LIBSIGSCAN_PATTERN_OFFSET_MODE_UNBOUND )
			{
				pattern_offset = 0;
			}
#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: signature: %s, pattern offset: %" PRIi64 " (%" PRIi64 "), pattern:\n",
				 function,
				 signature->identifier,
				 pattern_offset,
				 signature->pattern_offset );
				libcnotify_print_data(
				 signature->pattern,
				 signature->pattern_size,
				 0 );
			}
#endif
			for( pattern_index = 0;
			     pattern_index < signature->pattern_size;
			     pattern_index++ )
			{
				result = libsigscan_offsets_list_has_offset(
					  offsets_ignore_list,
					  pattern_offset,
					  error );

				if( result == -1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
					 "%s: unable to determine if offsets ignore list contains: %" PRIi64 ".",
					 function,
					 pattern_offset );

					return( -1 );
				}
				else if( result == 0 )
				{
					if( libsigscan_signature_table_insert_signature(
					     signature_table,
					     pattern_offset,
					     signature->pattern[ pattern_index ],
					     signature,
					     error ) != 1 )
					{
						libcerror_error_set(
						 error,
						 LIBCERROR_ERROR_DOMAIN_RUNTIME,
						 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
						 "%s: unable to insert signature into signature table.",
						 function );

						return( -1 );
					}
				}
				pattern_offset++;
			}
			if( libcdata_list_append_value(
			     signature_table->signatures_list,
			     (intptr_t *) signature,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
				 "%s: unable to append signature.",
				 function );

				return( -1 );
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

/* Retrieves the number of byte value groups
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_table_get_number_of_byte_value_groups(
     libsigscan_signature_table_t *signature_table,
     int *number_of_byte_value_groups,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_table_get_number_of_byte_value_groups";

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_number_of_elements(
	     signature_table->byte_value_groups_list,
	     number_of_byte_value_groups,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of byte value groups.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a specific byte value group
 * Returns 1 if successful, 0 if no such value or -1 on error
 */
int libsigscan_signature_table_get_byte_value_group_by_index(
     libsigscan_signature_table_t *signature_table,
     int byte_value_group_index,
     libsigscan_byte_value_group_t **byte_value_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_table_get_byte_value_group_by_index";

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_value_by_index(
	     signature_table->byte_value_groups_list,
	     byte_value_group_index,
	     (intptr_t **) byte_value_group,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve byte value group: %d.",
		 function,
		 byte_value_group_index );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a specific byte value group by offset
 * Returns 1 if successful, 0 if no such value or -1 on error
 */
int libsigscan_signature_table_get_byte_value_group_by_offset(
     libsigscan_signature_table_t *signature_table,
     off64_t pattern_offset,
     libsigscan_byte_value_group_t **byte_value_group,
     libcerror_error_t **error )
{
	libcdata_list_element_t *list_element = NULL;
	static char *function                 = "libsigscan_signature_table_get_byte_value_group_by_offset";
	int result                            = 0;

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	if( byte_value_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte value group.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_first_element(
	     signature_table->byte_value_groups_list,
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
		     (intptr_t **) byte_value_group,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve byte value group.",
			 function );

			return( -1 );
		}
		if( *byte_value_group == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: missing byte value group.",
			 function );

			return( -1 );
		}
		if( ( *byte_value_group )->pattern_offset == pattern_offset )
		{
			result = 1;

			break;
		}
		if( ( *byte_value_group )->pattern_offset > pattern_offset )
		{
			break;
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
	if( result == 0 )
	{
		*byte_value_group = NULL;
	}
	return( result );
}

/* Retrieves the number of signatures
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_table_get_number_of_signatures(
     libsigscan_signature_table_t *signature_table,
     int *number_of_signatures,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_table_get_number_of_signatures";

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_number_of_elements(
	     signature_table->signatures_list,
	     number_of_signatures,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of signatures.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a clone of the signatures list
 * Returns 1 if successful, 0 if no such value or -1 on error
 */
int libsigscan_signature_table_get_signatures_list_clone(
     libsigscan_signature_table_t *signature_table,
     libcdata_list_t **signatures_list,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_signature_table_get_signatures_list_clone";

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	if( libcdata_list_clone(
	     signatures_list,
	     signature_table->signatures_list,
	     (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_signature_free_clone,
	     (int (*)(intptr_t **, intptr_t *, libcerror_error_t **)) &libsigscan_signature_clone,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to clone remaining signatures list.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Inserts a signature for a specific pattern offset and byte value
 * Returns 1 if successful or -1 on error
 */
int libsigscan_signature_table_insert_signature(
     libsigscan_signature_table_t *signature_table,
     off64_t pattern_offset,
     uint8_t byte_value,
     libsigscan_signature_t *signature,
     libcerror_error_t **error )
{
	libsigscan_byte_value_group_t *byte_value_group = NULL;
	static char *function                           = "libsigscan_signature_table_insert_signature";
	int result                                      = 0;

	if( signature_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature table.",
		 function );

		return( -1 );
	}
	result = libsigscan_signature_table_get_byte_value_group_by_offset(
	          signature_table,
	          pattern_offset,
	          &byte_value_group,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve byte value group for pattern offset: %" PRIi64 ".",
		 function,
		 pattern_offset );

		return( -1 );
	}
	else if( result == 0 )
	{
		if( libsigscan_byte_value_group_initialize(
		     &byte_value_group,
		     pattern_offset,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create byte value group for pattern offset: %" PRIi64 ".",
			 function,
			 pattern_offset );

			return( -1 );
		}
		if( libcdata_list_insert_value(
		     signature_table->byte_value_groups_list,
		     (intptr_t *) byte_value_group,
		     (int (*)(intptr_t *, intptr_t *, libcerror_error_t **)) &libsigscan_byte_value_group_compare,
		     LIBCDATA_INSERT_FLAG_UNIQUE_ENTRIES,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
			 "%s: unable to insert byte value group for pattern offset: %" PRIi64 " into byte value groups list.",
			 function,
			 pattern_offset );

			libsigscan_byte_value_group_free(
			 &byte_value_group,
			 NULL );

			return( -1 );
		}
	}
	if( libsigscan_byte_value_group_insert_signature(
	     byte_value_group,
	     byte_value,
	     signature,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to insert signature into byte value group for pattern offset: %" PRIi64 ".",
		 function,
		 pattern_offset );

		return( -1 );
	}
	return( 1 );
}

