/*
 * The weight group functions
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

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_weight_group.h"

/* Frees a weight
 * Returns 1 if successful or -1 on error
 */
int libsigscan_weight_free(
     int **weight,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_weight_free";

	if( weight == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid weight.",
		 function );

		return( -1 );
	}
	if( *weight != NULL )
	{
		memory_free(
		 *weight );

		*weight = NULL;
	}
	return( 1 );
}

/* Creates a weight group
 * Make sure the value weight_group is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_weight_group_initialize(
     libsigscan_weight_group_t **weight_group,
     off64_t pattern_offset,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_weight_group_initialize";

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
	if( *weight_group != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid weight group value already set.",
		 function );

		return( -1 );
	}
	*weight_group = memory_allocate_structure(
	                 libsigscan_weight_group_t );

	if( *weight_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create weight group.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *weight_group,
	     0,
	     sizeof( libsigscan_weight_group_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear weight group.",
		 function );

		memory_free(
		 *weight_group );

		*weight_group = NULL;

		return( -1 );
	}
	( *weight_group )->pattern_offset = pattern_offset;

	return( 1 );

on_error:
	if( *weight_group != NULL )
	{
		memory_free(
		 *weight_group );

		*weight_group = NULL;
	}
	return( -1 );
}

/* Frees a weight group
 * Returns 1 if successful or -1 on error
 */
int libsigscan_weight_group_free(
     libsigscan_weight_group_t **weight_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_weight_group_free";

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
	if( *weight_group != NULL )
	{
		memory_free(
		 *weight_group );

		*weight_group = NULL;
	}
	return( 1 );
}

/* Compares two weight groups
 * Returns return LIBCDATA_COMPARE_LESS, LIBCDATA_COMPARE_EQUAL, LIBCDATA_COMPARE_GREATER if successful or -1 on error
 */
int libsigscan_weight_group_compare(
     libsigscan_weight_group_t *first_weight_group,
     libsigscan_weight_group_t *second_weight_group,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_weight_group_compare";

	if( first_weight_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid first weight group.",
		 function );

		return( -1 );
	}
	if( second_weight_group == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid second weight group.",
		 function );

		return( -1 );
	}
	if( first_weight_group->pattern_offset < second_weight_group->pattern_offset )
	{
		return( LIBCDATA_COMPARE_LESS );
	}
	else if( first_weight_group->pattern_offset > second_weight_group->pattern_offset )
	{
		return( LIBCDATA_COMPARE_GREATER );
	}
	return( LIBCDATA_COMPARE_EQUAL );
}

/* Adds a weight to the weight group
 * Returns 1 if successful or -1 on error
 */
int libsigscan_weight_group_add_weight(
     libsigscan_weight_group_t *weight_group,
     int weight,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_weight_group_add_weight";

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
	weight_group->weight += weight;

	return( 1 );
}

/* Retrieves the weight
 * Returns 1 if successful or -1 on error
 */
int libsigscan_weight_group_get_weight(
     libsigscan_weight_group_t *weight_group,
     int *weight,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_weight_group_get_weight";

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
	if( weight == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid weight.",
		 function );

		return( -1 );
	}
	*weight = weight_group->weight;

	return( 1 );
}

/* Sets the weight
 * Returns 1 if successful or -1 on error
 */
int libsigscan_weight_group_set_weight(
     libsigscan_weight_group_t *weight_group,
     int weight,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_weight_group_set_weight";

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
	weight_group->weight = weight;

	return( 1 );
}

