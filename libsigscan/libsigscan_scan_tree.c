/*
 * Scan tree functions
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

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_pattern_weights.h"
#include "libsigscan_scan_tree.h"
#include "libsigscan_signature_table.h"

uint8_t libsigscan_common_byte_values[ 256 ] = {
/*                           \a \b \t \n \v \f \r      */
	1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/*         !  "  #  $  %  &  '  (  )  *  +  ,  -  .  / */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/*      0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ? */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
/*      @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O */
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
/*      P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _ */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
/*      `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o */
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
/*      p  q  r  s  t  y  v  w  x  y  z  {  |  }  ~    */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};

/* Creates scan tree
 * Make sure the value scan_tree is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_initialize(
     libsigscan_scan_tree_t **scan_tree,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_initialize";

	if( scan_tree == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree.",
		 function );

		return( -1 );
	}
	if( *scan_tree != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid scan tree value already set.",
		 function );

		return( -1 );
	}
	*scan_tree = memory_allocate_structure(
	              libsigscan_scan_tree_t );

	if( *scan_tree == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create scan tree.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *scan_tree,
	     0,
	     sizeof( libsigscan_scan_tree_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear scan tree.",
		 function );

		memory_free(
		 *scan_tree );

		*scan_tree = NULL;

		return( -1 );
	}
	return( 1 );

on_error:
	if( *scan_tree != NULL )
	{
		memory_free(
		 *scan_tree );

		*scan_tree = NULL;
	}
	return( -1 );
}

/* Frees scan tree
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_free(
     libsigscan_scan_tree_t **scan_tree,
     libcerror_error_t **error )
{
	static char *function = "libsigscan_scan_tree_free";

	if( scan_tree == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree.",
		 function );

		return( -1 );
	}
	if( *scan_tree != NULL )
	{
		memory_free(
		 *scan_tree );

		*scan_tree = NULL;
	}
	return( 1 );
}

/* Builds a scan tree node
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_build_node(
     libsigscan_scan_tree_t *scan_tree,
     libsigscan_signature_table_t *signature_table,
     libcdata_tree_node_t **tree_node,
     libcerror_error_t **error )
{
	libsigscan_pattern_weights_t *byte_value_weights = NULL;
	libsigscan_pattern_weights_t *occurrence_weights = NULL;
	libsigscan_pattern_weights_t *similarity_weights = NULL;
	static char *function                            = "libsigscan_scan_tree_build_node";
	off64_t pattern_offset                           = 0;
	uint8_t byte_value                               = 0;
	int byte_value_index                             = 0;
	int byte_value_weight                            = 0;
	int number_of_byte_values                        = 0;
	int number_of_pattern_offsets                    = 0;
	int number_of_signatures                         = 0;
	int pattern_offset_index                         = 0;

	if( scan_tree == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree.",
		 function );

		return( -1 );
	}
	if( libsigscan_pattern_weights_initialize(
	     &occurrence_weights,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create occurrence weights.",
		 function );

		goto on_error;
	}
	if( libsigscan_pattern_weights_initialize(
	     &similarity_weights,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create similarity weights.",
		 function );

		goto on_error;
	}
	if( libsigscan_pattern_weights_initialize(
	     &byte_value_weights,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create byte value weights.",
		 function );

		goto on_error;
	}
/* TODO for each pattern offset in the pattern table */
	for( pattern_offset_index = 0;
	     pattern_offset_index < number_of_pattern_offsets;
	     pattern_offset_index++ )
	{
/* TODO get pattern offset */
		pattern_offset = 0;

/* TODO determine the number of byte values per pattern offset */
		number_of_byte_values = 0;

		if( number_of_byte_values > 1 )
		{
			if( libsigscan_pattern_weights_set_weight(
			     occurrence_weights,
			     pattern_offset,
			     number_of_byte_values,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
				 "%s: unable to set occurrence weight.",
				 function );

				goto on_error;
			}
		}
		for( byte_value_index = 0;
		     byte_value_index < number_of_byte_values;
		     byte_value_index++ )
		{
/* TODO determine byte_value_weight */
/* TODO determine the number of signatures per byte value */
			number_of_signatures = 0;

			if( number_of_signatures > 1 )
			{
				if( libsigscan_pattern_weights_add_weight(
				     similarity_weights,
				     pattern_offset,
				     byte_value_weight,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
					 "%s: unable to add similarity weight.",
					 function );

					goto on_error;
				}
			}
			if( libsigscan_common_byte_values[ byte_value ] == 0 )
			{
				if( libsigscan_pattern_weights_add_weight(
				     byte_value_weights,
				     pattern_offset,
				     1,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
					 "%s: unable to add byte value weight.",
					 function );

					goto on_error;
				}
			}
		}
	}
/* TODO get most significant pattern offset */

/* TODO fill scan tree node */

	if( libsigscan_pattern_weights_free(
	     &byte_value_weights,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free value weights.",
		 function );

		goto on_error;
	}
	if( libsigscan_pattern_weights_free(
	     &similarity_weights,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free similarity weights.",
		 function );

		goto on_error;
	}
	if( libsigscan_pattern_weights_free(
	     &occurrence_weights,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free occurrence weights.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( byte_value_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &byte_value_weights,
		 NULL );
	}
	if( similarity_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &similarity_weights,
		 NULL );
	}
	if( occurrence_weights != NULL )
	{
		libsigscan_pattern_weights_free(
		 &occurrence_weights,
		 NULL );
	}
	return( -1 );
}

/* Builds the scan tree
 * Returns 1 if successful or -1 on error
 */
int libsigscan_scan_tree_build(
     libsigscan_scan_tree_t *scan_tree,
     libcdata_array_t *signatures_array,
     libcerror_error_t **error )
{
	libsigscan_signature_table_t *signature_table = NULL;
	static char *function                         = "libsigscan_scan_tree_build";

	if( scan_tree == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid scan tree.",
		 function );

		return( -1 );
	}
	if( libsigscan_signature_table_initialize(
	     &signature_table,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create signature table.",
		 function );

		goto on_error;
	}
	if( libsigscan_signature_table_fill(
	     signature_table,
	     signatures_array,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to fill signature table.",
		 function );

		goto on_error;
	}
	if( libsigscan_scan_tree_build_node(
	     scan_tree,
	     signature_table,
	     &( scan_tree->root_node ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to build scan tree root node.",
		 function );

		goto on_error;
	}
/* TODO create skip table */
/* TODO determine largest pattern size */

	if( libsigscan_signature_table_free(
	     &signature_table,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free signature table.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( signature_table != NULL )
	{
		libsigscan_signature_table_free(
		 &signature_table,
		 NULL );
	}
	return( -1 );
}

