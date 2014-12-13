/*
 * Debug functions
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
#include <types.h>

#include "libsigscan_debug.h"
#include "libsigscan_definitions.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_libcnotify.h"
#include "libsigscan_skip_table.h"

#if defined( HAVE_DEBUG_OUTPUT )

/* Prints a skip table
 * Returns 1 if successful or -1 on error
 */
int libsigscan_debug_print_skip_table(
     libsigscan_skip_table_t *skip_table,
     libcerror_error_t **error )
{
	static char *function    = "libsigscan_debug_print_skip_table";
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
         skip_table->skip_pattern_size );

	libcnotify_printf(
	 "\n" );

	return( 1 );
}

#endif

