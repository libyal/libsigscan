/*
 * Scan state functions
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

#include "libsigscan_definitions.h"
#include "libsigscan_libcerror.h"
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

		memory_free(
		 internal_scan_state );
	}
	return( 1 );
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

/* Starts the scan state
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_start(
     libsigscan_scan_state_t *scan_state,
     libsigscan_scan_tree_node_t *active_node,
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

	if( internal_scan_state->state != LIBSIGSCAN_SCAN_STATE_INITIALIZED )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid scan state - unsupported state.",
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
	if( active_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid active scan tree node.",
		 function );

		return( -1 );
	}
	internal_scan_state->state       = LIBSIGSCAN_SCAN_STATE_STARTED;
	internal_scan_state->active_node = active_node;

	return( 1 );
}

/* Updates the scan state
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_state_update(
     libsigscan_scan_state_t *scan_state,
     libsigscan_scan_tree_node_t *active_node,
     libcerror_error_t **error )
{
	libsigscan_internal_scan_state_t *internal_scan_state = NULL;
	static char *function                                 = "libsigscan_scan_state_update";

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
	if( active_node == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid active scan tree node.",
		 function );

		return( -1 );
	}
	internal_scan_state->active_node = active_node;

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
	internal_scan_state->state       = LIBSIGSCAN_SCAN_STATE_STOPPED;
	internal_scan_state->active_node = NULL;

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

/* TODO */
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

/* TODO */
	return( 1 );
}

