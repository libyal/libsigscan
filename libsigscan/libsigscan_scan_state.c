/*
 * Scan state functions
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

#include "libsigscan_definitions.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_libcnotify.h"
#include "libsigscan_scan_result.h"
#include "libsigscan_scan_state.h"
#include "libsigscan_types.h"

/* Creates scan state
 * Make sure the value scan_state is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_initialize(
     libsigscan_scan_state_t **scan_state,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_initialize";

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	if( *scan_state != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan state value already set.",
		 function );

		return( -1 );
	}
	internal_scan_state = memory_allocate_structure(
	                       libsigscan_internal_scan_state_t );

	if( internal_scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan state.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_scan_state,
	     0,
	     sizeof( libsigscan_internal_scan_state_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear scan state.",
		 function );

		memory_free(
		 internal_scan_state );

		return( -1 );
	}
	if( libcdata_array_initialize(
	     &( internal_scan_state->scan_results_array ),
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create scan results array.",
		 function );

		goto on_error;
	}
	internal_scan_state->state = LIBSIGSCAN_SCAN_STATE_INITIALIZED;

	*scan_state = (libsigscan_scan_state_t *) internal_scan_state;

	return( 1 );

on_error:
	if( internal_scan_state != NULL )
	{
		memory_free(
		 internal_scan_state );
	}
	return( -1 );
}

/* Frees scan state
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_free(
     libsigscan_scan_state_t **scan_state,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_free";
	int result                                            = 1;

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	if( *scan_state != NULL )
	{
		internal_scan_state = (libsigscan_internal_scan_state_t *) *scan_state;
		*scan_state         = NULL;

		/* The scan_tree and active_node are references and freed elsewhere
		 */
		if( internal_scan_state->buffer != NULL )
		{
			memory_free(
			 internal_scan_state->buffer );
		}
		if( libcdata_array_free(
		     &( internal_scan_state->scan_results_array ),
		     (int (*)(intptr_t **, libcerror_error_t **)) &libsigscan_internal_scan_result_free,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free scan results array.",
			 function );

			result = -1;
		}
		memory_free(
		 internal_scan_state );
	}
	return( result );
}

/* Sets the data size
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_set_data_size(
     libsigscan_scan_state_t *scan_state,
     size64_t data_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_get_number_of_results";

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	internal_scan_state = (libsigscan_internal_scan_state_t *) scan_state;

	if( data_size == 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_ZERO_OR_LESS,
		 "%s: invalid data size value zero or less.",
		 function );

		return( -1 );
	}
	if( data_size > (size64_t) INT64_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	internal_scan_state->data_size = data_size;

	return( 1 );
}

/* Retrieves the buffer size
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_get_buffer_size(
     libsigscan_scan_state_t *scan_state,
     size_t *buffer_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_get_buffer_size";

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	internal_scan_state = (libsigscan_internal_scan_state_t *) scan_state;

	if( buffer_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	*buffer_size = internal_scan_state->buffer_size;

	return( 1 );
}

/* Starts the scan state
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_start(
     libsigscan_scan_state_t *scan_state,
     libsigscan_scan_tree_t *scan_tree,
     size_t scan_buffer_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_start";

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	internal_scan_state = (libsigscan_internal_scan_state_t *) scan_state;

	if( ( internal_scan_state->state != LIBSIGSCAN_SCAN_STATE_INITIALIZED )
	 && ( internal_scan_state->state != LIBSIGSCAN_SCAN_STATE_STOPPED ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid scan state - unsupported state.",
		 function );

		return( -1 );
	}
	if( internal_scan_state->buffer != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan state - buffer value already set.",
		 function );

		return( -1 );
	}
	if( internal_scan_state->data_size == 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid scan state - data size not set.",
		 function );

		return( -1 );
	}
	if( scan_tree == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid active scan tree.",
		 function );

		return( -1 );
	}
	if( scan_buffer_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid scan buffer size value exceeds maximum.",
		 function );

		return( -1 );
	}
	internal_scan_state->buffer = (uint8_t *) memory_allocate(
	                                           sizeof( uint8_t ) * scan_buffer_size );

	if( internal_scan_state->buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan buffer.",
		 function );

		return( -1 );
	}
	internal_scan_state->buffer_size       = scan_buffer_size;
	internal_scan_state->buffer_data_size  = 0;
	internal_scan_state->state             = LIBSIGSCAN_SCAN_STATE_STARTED;
	internal_scan_state->scan_tree         = scan_tree;
	internal_scan_state->active_node       = internal_scan_state->scan_tree->root_node;
	internal_scan_state->scanned_data_size = 0;

	return( 1 );
}

/* Stops the scan state
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_stop(
     libsigscan_scan_state_t *scan_state,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_stop";

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	internal_scan_state = (libsigscan_internal_scan_state_t *) scan_state;

	if( internal_scan_state->state != LIBSIGSCAN_SCAN_STATE_STARTED )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid scan state - unsupported state.",
		 function );

		return( -1 );
	}
	if( libsigscan_internal_scan_state_scan_buffer(
	     internal_scan_state,
	     internal_scan_state->buffer,
	     internal_scan_state->buffer_data_size,
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to scan buffer.",
		 function );

		return( -1 );
	}
	if( internal_scan_state->buffer != NULL )
	{
		memory_free(
		 internal_scan_state->buffer );

		internal_scan_state->buffer = NULL;
	}
	internal_scan_state->buffer_size = 0;
	internal_scan_state->state       = LIBSIGSCAN_SCAN_STATE_STOPPED;
	internal_scan_state->active_node = NULL;

	return( 1 );
}

/* Scans the buffer and updates the scan state
 * Returns 1 if successful, 0 if data size has been reached or -1 on error
 */
int libsigscan_internal_scan_state_scan_buffer(
     libsigscan_internal_scan_state_t *internal_scan_state,
     const uint8_t *buffer,
     size_t buffer_size,
     size_t buffer_offset,
     libcerror_error_t **error )
{
	libsigscan_scan_object_t *scan_object = NULL;
	libsigscan_scan_result_t *scan_result = NULL;
	libsigscan_signature_t *signature     = NULL;
	static char *function                 = "libsigscan_internal_scan_state_scan_buffer";
	off64_t scan_result_offset            = 0;
	size_t buffer_end_offset              = 0;
	size_t skip_value                     = 0;
	size_t smallest_pattern_size          = 0;
	uint8_t scan_object_type              = 0;
	int entry_index                       = 0;
	int result                            = 0;

	if( internal_scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid internal scan state.",
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
	if( buffer_offset >= buffer_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid buffer offset value out of bounds.",
		 function );

		return( -1 );
	}
	while( buffer_offset < buffer_size )
	{
		result = libsigscan_scan_tree_node_scan_buffer(
		          internal_scan_state->active_node,
		          buffer,
		          buffer_size,
		          buffer_offset,
		          &scan_object,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to scan buffer.",
			 function );

			goto on_error;
		}
		else if( result != 0 )
		{
			if( libsigscan_scan_object_get_type(
			     scan_object,
			     &scan_object_type,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve scan object type.",
				 function );

				goto on_error;
			}
			if( scan_object_type != LIBSIGSCAN_SCAN_OBJECT_TYPE_SIGNATURE )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
				 "%s: unsupported scan object type.",
				 function );

				goto on_error;
			}
			if( libsigscan_scan_object_get_value(
			     scan_object,
			     (intptr_t **) &signature,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve scan object value.",
				 function );

				goto on_error;
			}
			if( signature == NULL )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
				 "%s: missing signature.",
				 function );

				goto on_error;
			}
			result = memory_compare(
				  &( buffer[ buffer_offset ] ),
				  signature->pattern,
				  signature->pattern_size );

			result = ( result == 0 );

			if( result != 0 )
			{
#if defined( HAVE_DEBUG_OUTPUT )
				if( libcnotify_verbose != 0 )
				{
					scan_result_offset = internal_scan_state->scanned_data_size
					                   + buffer_offset
					                   - internal_scan_state->buffer_data_size;

					libcnotify_printf(
					 "%s: match for signature: %s at offset: %" PRIi64 ".\n",
					 function,
					 signature->identifier,
					 scan_result_offset );
				}
#endif
/* TODO add support for unbounded signatures */
				result = ( buffer_offset == signature->pattern_offset );
			}
			if( result != 0 )
			{
				scan_result_offset = internal_scan_state->scanned_data_size
				                   + buffer_offset
				                   - internal_scan_state->buffer_data_size;

				if( libsigscan_scan_result_initialize(
				     &scan_result,
				     scan_result_offset,
				     signature,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
					 "%s: unable to create scan result.",
					 function );

					goto on_error;
				}
				if( libcdata_array_append_entry(
				     internal_scan_state->scan_results_array,
				     &entry_index,
				     (intptr_t *) scan_result,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
					 "%s: unable to append scan result.",
					 function );

					goto on_error;
				}
				scan_result = NULL;

				skip_value = signature->pattern_size;
			}
		}
		if( result == 0 )
		{
			if( libsigscan_skip_table_get_smallest_pattern_size(
			     internal_scan_state->scan_tree->skip_table,
			     &smallest_pattern_size,
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
			if( smallest_pattern_size > buffer_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: invalid smallest pattern size value out of bounds.",
				 function );

				goto on_error;
			}
			buffer_end_offset = buffer_offset + smallest_pattern_size - 1;

			if( buffer_end_offset >= buffer_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: invalid scan end offset value out of bounds.",
				 function );

				goto on_error;
			}
			skip_value = 0;

			do
			{
				if( libsigscan_skip_table_get_skip_value(
				     internal_scan_state->scan_tree->skip_table,
				     buffer[ buffer_end_offset ],
				     &skip_value,
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
				buffer_end_offset -= 1;
			}
			while( ( buffer_end_offset > buffer_offset )
			    && ( skip_value == 0 ) );
		}
		internal_scan_state->active_node = internal_scan_state->scan_tree->root_node;

		buffer_offset += skip_value;
	}
	return( 1 );

on_error:
	if( scan_result != NULL )
	{
		libsigscan_internal_scan_result_free(
		 (libsigscan_internal_scan_result_t **) &scan_result,
		 NULL );
	}
	return( -1 );
}

/* Scans the buffer and updates the scan state
 * Returns 1 if successful, 0 if data size has been reached or -1 on error
 */
int libsigscan_scan_state_scan_buffer(
     libsigscan_scan_state_t *scan_state,
     const uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_scan_buffer";
	size_t buffer_offset                                  = 0;
	size_t read_size                                      = 0;
	size_t scan_size                                      = 0;

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	internal_scan_state = (libsigscan_internal_scan_state_t *) scan_state;

	if( internal_scan_state->state != LIBSIGSCAN_SCAN_STATE_STARTED )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid scan state - unsupported state.",
		 function );

		return( -1 );
	}
	if( internal_scan_state->scan_tree == 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid scan state - missing scan tree.",
		 function );

		return( -1 );
	}
	if( internal_scan_state->active_node == 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid scan state - missing active scan tree node.",
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
	if( internal_scan_state->scanned_data_size > internal_scan_state->data_size )
	{
		return( 0 );
	}
	if( ( (size64_t) buffer_size > internal_scan_state->data_size )
	 || ( internal_scan_state->scanned_data_size > ( internal_scan_state->data_size - buffer_size ) ) )
	{
		buffer_size = (size_t) ( internal_scan_state->data_size - internal_scan_state->scanned_data_size );
	}
	read_size = buffer_size;

	if( internal_scan_state->buffer_data_size == internal_scan_state->buffer_size )
	{
		read_size -= internal_scan_state->buffer_data_size;

		if( memory_copy(
		     &( internal_scan_state->buffer[ internal_scan_state->buffer_data_size ] ),
		     buffer,
		     read_size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy buffer to scan buffer.",
			 function );

			return( -1 );
		}
		internal_scan_state->buffer_data_size += read_size;
		buffer_offset                         += read_size;

		if( libsigscan_internal_scan_state_scan_buffer(
		     internal_scan_state,
		     internal_scan_state->buffer,
		     internal_scan_state->buffer_size,
		     0,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to scan buffer.",
			 function );

			return( -1 );
		}
	}
	if( read_size >= internal_scan_state->buffer_size )
	{
		scan_size  = ( read_size / internal_scan_state->buffer_size );
		scan_size *= internal_scan_state->buffer_size;

		if( libsigscan_internal_scan_state_scan_buffer(
		     internal_scan_state,
		     buffer,
		     buffer_offset + scan_size,
		     buffer_offset,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to scan buffer.",
			 function );

			return( -1 );
		}
		read_size     -= scan_size;
		buffer_offset += scan_size;
	}
	if( read_size > 0 )
	{
		if( memory_copy(
		     internal_scan_state->buffer,
		     &( buffer[ buffer_offset ] ),
		     read_size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy buffer to scan buffer.",
			 function );

			return( -1 );
		}
		internal_scan_state->buffer_data_size = read_size;
	}
	internal_scan_state->scanned_data_size += buffer_size;

	return( 1 );
}

/* Retrieves the number of scan results
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_get_number_of_results(
     libsigscan_scan_state_t *scan_state,
     int *number_of_results,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_get_number_of_results";

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	internal_scan_state = (libsigscan_internal_scan_state_t *) scan_state;

	if( libcdata_array_get_number_of_entries(
	     internal_scan_state->scan_results_array,
	     number_of_results,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of scan results.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a specific scan result
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_get_result(
     libsigscan_scan_state_t *scan_state,
     int result_index,
     libsigscan_scan_result_t **scan_result,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_get_result";

	if( scan_state == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	internal_scan_state = (libsigscan_internal_scan_state_t *) scan_state;

	if( libcdata_array_get_entry_by_index(
	     internal_scan_state->scan_results_array,
	     result_index,
	     (intptr_t **) scan_result,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve scan result: %d.",
		 function,
		 result_index );

		return( -1 );
	}
	return( 1 );
}

