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
#include "sigscantools_libcerror.h"
#include "sigscantools_libsigscan.h"

/* Creates signature definitions
 * Make sure the value signatures_definitions is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int signatures_definitions_initialize(
     signatures_definitions_t **signatures_definitions,
     libcerror_error_t **error )
{
	static char *function = "signatures_definitions_initialize";

	if( signatures_definitions == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature definitions.",
		 function );

		return( -1 );
	}
	if( *signatures_definitions != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid signature definitions value already set.",
		 function );

		return( -1 );
	}
	*signatures_definitions = memory_allocate_structure(
	                           signatures_definitions_t );

	if( *signatures_definitions == NULL )
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
	     *signatures_definitions,
	     0,
	     sizeof( signatures_definitions_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear signature definitions.",
		 function );

		memory_free(
		 *signatures_definitions );

		*signatures_definitions = NULL;

		return( -1 );
	}
	return( 1 );

on_error:
	if( *signatures_definitions != NULL )
	{
		memory_free(
		 *signatures_definitions );

		*signatures_definitions = NULL;
	}
	return( -1 );
}

/* Frees signature definitions
 * Returns 1 if successful or -1 on error
 */
int signatures_definitions_free(
     signatures_definitions_t **signatures_definitions,
     libcerror_error_t **error )
{
	static char *function = "signatures_definitions_free";
	int result            = 1;

	if( signatures_definitions == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid signature definitions.",
		 function );

		return( -1 );
	}
	if( *signatures_definitions != NULL )
	{
		memory_free(
		 *signatures_definitions );

		*signatures_definitions = NULL;
	}
	return( result );
}

