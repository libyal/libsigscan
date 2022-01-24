/*
 * Scan tree node functions
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

#include "libsigscan_definitions.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_libcnotify.h"
#include "libsigscan_scan_object.h"
#include "libsigscan_scan_tree_node.h"
#include "libsigscan_signature.h"

/* Creates scan tree node
 * Make sure the value scan_tree_node is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_node_initialize(
     libsigscan_scan_tree_node_t **scan_tree_node,
     off64_t pattern_offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_node_initialize";

	if( scan_tree_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree node.",
		 function );

		return( -1 );
	}
	if( *scan_tree_node != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan tree node value already set.",
		 function );

		return( -1 );
	}
	*scan_tree_node = memory_allocate_structure(
	                   libsigscan_scan_tree_node_t );

	if( *scan_tree_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan tree node.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *scan_tree_node,
	     0,
	     sizeof( libsigscan_scan_tree_node_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear scan tree node.",
		 function );

		memory_free(
		 *scan_tree_node );

		*scan_tree_node = NULL;

		return( -1 );
	}
	( *scan_tree_node )->pattern_offset = pattern_offset;

	return( 1 );

on_error:
	if( *scan_tree_node != NULL )
	{
		memory_free(
		 *scan_tree_node );

		*scan_tree_node = NULL;
	}
	return( -1 );
}

/* Frees scan tree node
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_node_free(
     libsigscan_scan_tree_node_t **scan_tree_node,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_node_free";
	uint16_t byte_value   = 0;
	int result            = 1;

	if( scan_tree_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree node.",
		 function );

		return( -1 );
	}
	if( *scan_tree_node != NULL )
	{
		for( byte_value = 0;
		     byte_value < 256;
		     byte_value++ )
		{
			if( ( *scan_tree_node )->scan_objects_table[ byte_value ] == NULL )
			{
				continue;
			}
			if( libsigscan_scan_object_free(
			     &( ( *scan_tree_node )->scan_objects_table[ byte_value ] ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free scan object for byte value: 0x%02" PRIx16 ".",
				 function,
				 byte_value );

				result = -1;
			}
		}
		if( libsigscan_scan_object_free(
		     &( ( *scan_tree_node )->default_scan_object ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free default scan object.",
			 function );

			result = -1;
		}
		memory_free(
		 *scan_tree_node );

		*scan_tree_node = NULL;
	}
	return( result );
}

/* Sets a scan object for a specific byte value
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_node_set_byte_value(
     libsigscan_scan_tree_node_t *scan_tree_node,
     uint8_t byte_value,
     libsigscan_scan_object_t *scan_object,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_node_set_byte_value";

	if( scan_tree_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree node.",
		 function );

		return( -1 );
	}
	if( scan_tree_node->scan_objects_table[ byte_value ] != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan tree node - scan object for byte value: 0x%02" PRIx8 " already set.",
		 function,
		 byte_value );

		return( -1 );
	}
	if( scan_object == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan object.",
		 function );

		return( -1 );
	}
	scan_tree_node->scan_objects_table[ byte_value ] = scan_object;

	return( 1 );
}

/* Sets the default scan object
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_node_set_default_value(
     libsigscan_scan_tree_node_t *scan_tree_node,
     libsigscan_scan_object_t *scan_object,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_node_set_default_value";

	if( scan_tree_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree node.",
		 function );

		return( -1 );
	}
	if( scan_tree_node->default_scan_object != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan tree node - default scan object already set.",
		 function );

		return( -1 );
	}
	if( scan_object == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan object.",
		 function );

		return( -1 );
	}
	scan_tree_node->default_scan_object = scan_object;

	return( 1 );
}

/* Retrieves the scan object for a specific byte value or the default if available
 * Returns 1 if successful, 0 if not or -1 on error
 */
int libsigscan_scan_tree_node_get_scan_object(
     libsigscan_scan_tree_node_t *scan_tree_node,
     uint8_t byte_value,
     libsigscan_scan_object_t **scan_object,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_node_get_scan_object";

	if( scan_tree_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree node.",
		 function );

		return( -1 );
	}
	if( scan_object == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan object.",
		 function );

		return( -1 );
	}
	*scan_object = scan_tree_node->scan_objects_table[ byte_value ];

	if( *scan_object != NULL )
	{
		return( 1 );
	}
	*scan_object = scan_tree_node->default_scan_object;

	if( *scan_object != NULL )
	{
		return( 1 );
	}
	return( 0 );
}

/* Scans the buffer for a scan object that matches
 * Returns 1 if successful, 0 if not or -1 on error
 */
int libsigscan_scan_tree_node_scan_buffer(
     libsigscan_scan_tree_node_t *scan_tree_node,
     int pattern_offsets_mode,
     off64_t data_offset,
     size64_t data_size,
     const uint8_t *buffer,
     size_t buffer_size,
     size_t buffer_offset,
     libsigscan_scan_object_t **scan_object,
     libcerror_error_t **error )
{
	libsigscan_signature_t *signature = NULL;
	static char *function             = "libsigscan_scan_tree_node_scan_buffer";
	off64_t pattern_offset            = 0;
	off64_t scan_offset               = 0;
	size64_t remaining_data_size      = 0;
	uint8_t byte_value                = 0;
	uint8_t scan_object_type          = 0;
	int result                        = 0;

	if( scan_tree_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree node.",
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
	if( ( data_offset < 0 )
	 || ( (size64_t) data_offset >= data_size ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid data offset value out of bounds.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( buffer_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid buffer size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( scan_object == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan object.",
		 function );

		return( -1 );
	}
	remaining_data_size = data_size - data_offset;

	do
	{
		if( buffer_offset >= buffer_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid buffer offset value out of bounds.",
			 function );

			return( -1 );
		}
		scan_offset = (off64_t) ( buffer_offset + scan_tree_node->pattern_offset );

		if( (size64_t) scan_offset >= remaining_data_size )
		{
			/* If the pattern offset exceeds the data size
			 * continue with the default scan object if available.
			 */
			*scan_object = scan_tree_node->default_scan_object;
			result       = ( *scan_object != NULL );
		}
		else if( scan_offset >= (off64_t) buffer_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid scan offset value out of bounds.",
			 function );

			return( -1 );
		}
		else
		{
			byte_value = buffer[ scan_offset ];

			result = libsigscan_scan_tree_node_get_scan_object(
			          scan_tree_node,
			          byte_value,
			          scan_object,
			          error );

#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				if( result == 1 )
				{
					libcnotify_printf(
					 "%s: offset: %" PRIi64 " ",
					 function,
					 scan_offset );

					if( scan_tree_node->scan_objects_table[ byte_value ] != NULL )
					{
						libcnotify_printf(
						 "scan object: byte value: 0x%02" PRIx8 "",
						 byte_value );
					}
					else if( scan_tree_node->default_scan_object != NULL )
					{
						libcnotify_printf(
						 "scan object: default" );
					}
					else
					{
						libcnotify_printf(
						 "scan object: N/A" );
					}
					libcnotify_printf(
					 ".\n" );
				}
			}
#endif
		}
		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve scan object.",
			 function );

			return( -1 );
		}
		else if( result != 0 )
		{
			if( libsigscan_scan_object_get_type(
			     *scan_object,
			     &scan_object_type,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve scan object type.",
				 function );

				return( -1 );
			}
			if( scan_object_type == LIBSIGSCAN_SCAN_OBJECT_TYPE_SCAN_TREE_NODE )
			{
				if( libsigscan_scan_object_get_value(
				     *scan_object,
				     (intptr_t **) &scan_tree_node,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
					 "%s: unable to retrieve scan object value.",
					 function );

					return( -1 );
				}
			}
			else if( scan_object_type == LIBSIGSCAN_SCAN_OBJECT_TYPE_SIGNATURE )
			{
				if( libsigscan_scan_object_get_value(
				     *scan_object,
				     (intptr_t **) &signature,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
					 "%s: unable to retrieve scan object value.",
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
				if( pattern_offsets_mode == LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_START )
				{
					pattern_offset = signature->pattern_offset;
				}
				else if( pattern_offsets_mode == LIBSIGSCAN_PATTERN_OFFSET_MODE_BOUND_TO_END )
				{
					pattern_offset = data_size - signature->pattern_offset;
				}
				scan_offset = buffer_offset + ( pattern_offset - data_offset );

				if( ( (size64_t) signature->pattern_size > remaining_data_size )
				 || ( (size64_t) scan_offset > ( remaining_data_size - signature->pattern_size ) ) )
				{
					/* If the pattern size exceeds the data size were are done scanning.
					 */
					result = 0;

					break;
				}
				if( ( signature->pattern_size > buffer_size )
				 || ( (size64_t) scan_offset > ( buffer_size - signature->pattern_size ) ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: invalid pattern size value out of bounds.",
					 function );

					return( -1 );
				}
				if( memory_compare(
				     &( buffer[ scan_offset ] ),
				     signature->pattern,
				     signature->pattern_size ) != 0 )
				{
					result = 0;

					break;
				}
				scan_offset += data_offset;

#if defined( HAVE_DEBUG_OUTPUT )
				if( libcnotify_verbose != 0 )
				{
					libcnotify_printf(
					 "%s: offset: %" PRIi64 " signature: %s.\n",
					 function,
					 scan_offset,
					 signature->identifier );
				}
#endif
/* TODO add support for unbounded signatures */
				result = ( scan_offset == pattern_offset );

				break;
			}
		}
	}
	while( result != 0 );

	return( result );
}

#if defined( HAVE_DEBUG_OUTPUT )

/* Prints the scan tree node
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_node_printf(
     libsigscan_scan_tree_node_t *scan_tree_node,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_node_printf";
	uint16_t byte_value   = 0;

	if( scan_tree_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree node.",
		 function );

		return( -1 );
	}
	libcnotify_printf(
	 "%s: scan tree node: 0x%08" PRIjx "\n",
	 function,
	 (intptr_t *) scan_tree_node );

	libcnotify_printf(
	 "%s: pattern offset: %" PRIi64 "\n",
	 function,
	 scan_tree_node->pattern_offset );

	for( byte_value = 0;
	     byte_value < 256;
	     byte_value++ )
	{
		if( scan_tree_node->scan_objects_table[ byte_value ] == NULL )
		{
			continue;
		}
		libcnotify_printf(
		 "%s: byte value: 0x%02" PRIx16 ": ",
		 function,
		 byte_value );

		if( libsigscan_scan_object_printf(
		     scan_tree_node->scan_objects_table[ byte_value ],
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_PRINT_FAILED,
			 "%s: unable to print scan object for byte value: 0x%02" PRIx16 ".",
			 function,
			 byte_value );

			return( -1 );
		}
		libcnotify_printf(
		 "\n" );
	}
	if( scan_tree_node->default_scan_object != NULL )
	{
		libcnotify_printf(
		 "%s: default: ",
		 function );

		if( libsigscan_scan_object_printf(
		     scan_tree_node->default_scan_object,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_PRINT_FAILED,
			 "%s: unable to print default scan object.",
			 function );

			return( -1 );
		}
		libcnotify_printf(
		 "\n" );
	}
	libcnotify_printf(
	 "\n" );

	return( 1 );
}

#endif /* defined( HAVE_DEBUG_OUTPUT ) */

