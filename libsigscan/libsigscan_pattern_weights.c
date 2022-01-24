/*
 * Pattern weights functions
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
#include "libsigscan_offset_group.h"
#include "libsigscan_pattern_weights.h"
#include "libsigscan_weight_group.h"

/* Creates pattern weights
 * Make sure the value pattern_weights is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_pattern_weights_initialize(
     libsigscan_pattern_weights_t **pattern_weights,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_pattern_weights_initialize";

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	if( *pattern_weights != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid pattern weights value already set.",
		 function );

		return( -1 );
	}
	*pattern_weights = memory_allocate_structure(
	                    libsigscan_pattern_weights_t );

	if( *pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create pattern weights.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *pattern_weights,
	     0,
	     sizeof( libsigscan_pattern_weights_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear pattern weights.",
		 function );

		memory_free(
		 *pattern_weights );

		*pattern_weights = NULL;

		return( -1 );
	}
	if( libcdata_list_initialize(
	     &( ( *pattern_weights )->offset_groups_list ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create offset groups list.",
		 function );

		goto on_error;
	}
	if( libcdata_list_initialize(
	     &( ( *pattern_weights )->weight_groups_list ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create weight groups list.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *pattern_weights != NULL )
	{
		if( ( *pattern_weights )->offset_groups_list != NULL )
		{
			libcdata_list_free(
			 &( ( *pattern_weights )->offset_groups_list ),
			 NULL,
			 NULL );
		}
		memory_free(
		 *pattern_weights );

		*pattern_weights = NULL;
	}
	return( -1 );
}

/* Frees pattern weights
 * Returns 1 if successful or -1 on error
 */
int libsigscan_pattern_weights_free(
     libsigscan_pattern_weights_t **pattern_weights,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_pattern_weights_free";
	int result            = 1;

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	if( *pattern_weights != NULL )
	{
		if( libcdata_list_free(
		     &( ( *pattern_weights )->offset_groups_list ),
		     (int (*)(intptr_t **,libcerror_error_t **)) &libsigscan_offset_group_free,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free offset groups list.",
			 function );

			result = -1;
		}
		if( libcdata_list_free(
		     &( ( *pattern_weights )->weight_groups_list ),
		     (int (*)(intptr_t **,libcerror_error_t **)) &libsigscan_weight_group_free,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free weight groups list.",
			 function );

			result = -1;
		}
		memory_free(
		 *pattern_weights );

		*pattern_weights = NULL;
	}
	return( result );
}

/* Adds a weight
 * Returns 1 if successful or -1 on error
 */
int libsigscan_pattern_weights_add_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_pattern_weights_add_weight";

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	if( libsigscan_pattern_weights_insert_offset(
	     pattern_weights,
	     pattern_offset,
	     weight,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to insert offset into pattern weights.",
		 function );

		return( -1 );
	}
	if( libsigscan_pattern_weights_insert_add_weight(
	     pattern_weights,
	     pattern_offset,
	     weight,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to insert weight into pattern weights.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Sets a weight
 * Returns 1 if successful or -1 on error
 */
int libsigscan_pattern_weights_set_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_pattern_weights_set_weight";

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	if( libsigscan_pattern_weights_insert_offset(
	     pattern_weights,
	     pattern_offset,
	     weight,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to insert offset into pattern weights.",
		 function );

		return( -1 );
	}
	if( libsigscan_pattern_weights_insert_set_weight(
	     pattern_weights,
	     pattern_offset,
	     weight,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to insert weight into pattern weights.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves the largest weight
 * Returns 1 if successful, 0 if not available or -1 on error
 */
int libsigscan_pattern_weights_get_largest_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     int *largest_weight,
     libcerror_error_t **error )
{
	libcdata_list_element_t *list_element   = NULL;
	libsigscan_offset_group_t *offset_group = NULL;
	static char *function                   = "libsigscan_pattern_weights_get_largest_weight";

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_last_element(
	     pattern_weights->offset_groups_list,
	     &list_element,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve last offset groups list element.",
		 function );

		return( -1 );
	}
	if( list_element == NULL )
	{
		return( 0 );
	}
	if( libcdata_list_element_get_value(
	     list_element,
	     (intptr_t **) &offset_group,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve last offset group.",
		 function );

		return( -1 );
	}
	if( libsigscan_offset_group_get_weight(
	     offset_group,
	     largest_weight,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve last offset group weight.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a specific offset group
 * Returns 1 if successful, 0 if no such value or -1 on error
 */
int libsigscan_pattern_weights_get_offset_group(
     libsigscan_pattern_weights_t *pattern_weights,
     int weight,
     libsigscan_offset_group_t **offset_group,
     libcerror_error_t **error )
{
	libcdata_list_element_t *list_element = NULL;
	static char *function                 = "libsigscan_pattern_weights_get_offset_group";
	int result                            = 0;

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	if( offset_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset group.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_first_element(
	     pattern_weights->offset_groups_list,
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
		     (intptr_t **) offset_group,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve offset group.",
			 function );

			return( -1 );
		}
		if( *offset_group == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: missing offset group.",
			 function );

			return( -1 );
		}
		if( ( *offset_group )->weight == weight )
		{
			result = 1;

			break;
		}
		if( ( *offset_group )->weight > weight )
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
		*offset_group = NULL;
	}
	return( result );
}

/* Inserts an offset for a specific weight
 * Returns 1 if successful or -1 on error
 */
int libsigscan_pattern_weights_insert_offset(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error )
{
	libsigscan_offset_group_t *offset_group = NULL;
	static char *function                   = "libsigscan_pattern_weights_insert_offset";
	int result                              = 0;

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	result = libsigscan_pattern_weights_get_offset_group(
	          pattern_weights,
	          weight,
	          &offset_group,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve offset group.",
		 function );

		return( -1 );
	}
	else if( result == 0 )
	{
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: adding offset group for weight: %d\n",
			 function,
			 weight );
		}
#endif
		if( libsigscan_offset_group_initialize(
		     &offset_group,
		     weight,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create offset group for weight: %d.",
			 function,
			 weight );

			return( -1 );
		}
		if( libcdata_list_insert_value(
		     pattern_weights->offset_groups_list,
		     (intptr_t *) offset_group,
		     (int (*)(intptr_t *, intptr_t *, libcerror_error_t **)) &libsigscan_offset_group_compare,
		     LIBCDATA_INSERT_FLAG_UNIQUE_ENTRIES,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
			 "%s: unable to insert offset group for weight: %d into offset groups list.",
			 function,
			 weight );

			libsigscan_offset_group_free(
			 &offset_group,
			 NULL );

			return( -1 );
		}
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: adding pattern offset: %" PRIi64 " to offset group for weight: %d\n",
		 function,
		 pattern_offset,
		 weight );
	}
#endif
	if( libsigscan_offset_group_append_offset(
	     offset_group,
	     pattern_offset,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
		 "%s: unable to append pattern offset to offset group for weight: %d.",
		 function,
		 weight );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a specific weight group
 * Returns 1 if successful, 0 if no such value or -1 on error
 */
int libsigscan_pattern_weights_get_weight_group(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     libsigscan_weight_group_t **weight_group,
     libcerror_error_t **error )
{
	libcdata_list_element_t *list_element = NULL;
	static char *function                 = "libsigscan_pattern_weights_get_weight_group";
	int result                            = 0;

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	if( weight_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid weight group.",
		 function );

		return( -1 );
	}
	if( libcdata_list_get_first_element(
	     pattern_weights->weight_groups_list,
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
		     (intptr_t **) weight_group,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve weight group.",
			 function );

			return( -1 );
		}
		if( *weight_group == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
			 "%s: missing weight group.",
			 function );

			return( -1 );
		}
		if( ( *weight_group )->pattern_offset == pattern_offset )
		{
			result = 1;

			break;
		}
		if( ( *weight_group )->pattern_offset > pattern_offset )
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
		*weight_group = NULL;
	}
	return( result );
}

/* Inserts and adds an weight for a specific offset
 * Returns 1 if successful or -1 on error
 */
int libsigscan_pattern_weights_insert_add_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error )
{
	libsigscan_weight_group_t *weight_group = NULL;
	static char *function                   = "libsigscan_pattern_weights_insert_add_weight";
	int result                              = 0;

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	result = libsigscan_pattern_weights_get_weight_group(
	          pattern_weights,
	          pattern_offset,
	          &weight_group,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve weight group.",
		 function );

		return( -1 );
	}
	else if( result == 0 )
	{
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: adding weight group for pattern offset: %" PRIi64 "\n",
			 function,
			 pattern_offset );
		}
#endif
		if( libsigscan_weight_group_initialize(
		     &weight_group,
		     pattern_offset,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create weight group for pattern offset: %" PRIi64 ".",
			 function,
			 pattern_offset );

			return( -1 );
		}
		if( libcdata_list_insert_value(
		     pattern_weights->weight_groups_list,
		     (intptr_t *) weight_group,
		     (int (*)(intptr_t *, intptr_t *, libcerror_error_t **)) &libsigscan_weight_group_compare,
		     LIBCDATA_INSERT_FLAG_UNIQUE_ENTRIES,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
			 "%s: unable to insert weight group for pattern offset: %" PRIi64 " into weight groups list.",
			 function,
			 pattern_offset );

			libsigscan_weight_group_free(
			 &weight_group,
			 NULL );

			return( -1 );
		}
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: adding weight: %d to weight group for pattern offset: %" PRIi64 "\n",
		 function,
		 weight,
		 pattern_offset );
	}
#endif
	if( libsigscan_weight_group_add_weight(
	     weight_group,
	     weight,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to add weight to weight group for pattern offset: %" PRIi64 ".",
		 function,
		 pattern_offset );

		return( -1 );
	}
	return( 1 );
}

/* Inserts and sets an weight for a specific offset
 * Returns 1 if successful or -1 on error
 */
int libsigscan_pattern_weights_insert_set_weight(
     libsigscan_pattern_weights_t *pattern_weights,
     off64_t pattern_offset,
     int weight,
     libcerror_error_t **error )
{
	libsigscan_weight_group_t *weight_group = NULL;
	static char *function                   = "libsigscan_pattern_weights_insert_set_weight";
	int result                              = 0;

	if( pattern_weights == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid pattern weights.",
		 function );

		return( -1 );
	}
	result = libsigscan_pattern_weights_get_weight_group(
	          pattern_weights,
	          pattern_offset,
	          &weight_group,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve weight group.",
		 function );

		return( -1 );
	}
	else if( result == 0 )
	{
		if( libsigscan_weight_group_initialize(
		     &weight_group,
		     pattern_offset,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create weight group.",
			 function );

			return( -1 );
		}
		if( libcdata_list_insert_value(
		     pattern_weights->weight_groups_list,
		     (intptr_t *) weight_group,
		     (int (*)(intptr_t *, intptr_t *, libcerror_error_t **)) &libsigscan_weight_group_compare,
		     LIBCDATA_INSERT_FLAG_UNIQUE_ENTRIES,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
			 "%s: unable to insert weight into weight groups list.",
			 function );

			libsigscan_weight_group_free(
			 &weight_group,
			 NULL );

			return( -1 );
		}
	}
	if( libsigscan_weight_group_set_weight(
	     weight_group,
	     weight,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set weight in weight group.",
		 function );

		return( -1 );
	}
	return( 1 );
}

