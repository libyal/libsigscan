/*
 * Scan tree node functions
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

#if !defined( _LIBSIGSCAN_SCAN_TREE_NODE_H )
#define _LIBSIGSCAN_SCAN_TREE_NODE_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcerror.h"
#include "libsigscan_scan_object.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_scan_tree_node libsigscan_scan_tree_node_t;

struct libsigscan_scan_tree_node
{
	/* The pattern offset
	 */
	off64_t pattern_offset;

	/* The table of scan objects per byte value
	 */
	libsigscan_scan_object_t *scan_objects_table[ 256 ];

	/* The default scan object
	 */
	libsigscan_scan_object_t *default_scan_object;
};

int libsigscan_scan_tree_node_initialize(
     libsigscan_scan_tree_node_t **scan_tree_node,
     off64_t pattern_offset,
     libcerror_error_t **error );

int libsigscan_scan_tree_node_free(
     libsigscan_scan_tree_node_t **scan_tree_node,
     libcerror_error_t **error );

int libsigscan_scan_tree_node_set_byte_value(
     libsigscan_scan_tree_node_t *scan_tree_node,
     uint8_t byte_value,
     libsigscan_scan_object_t *scan_object,
     libcerror_error_t **error );

int libsigscan_scan_tree_node_set_default_value(
     libsigscan_scan_tree_node_t *scan_tree_node,
     libsigscan_scan_object_t *scan_object,
     libcerror_error_t **error );

int libsigscan_scan_tree_node_get_scan_object(
     libsigscan_scan_tree_node_t *scan_tree_node,
     uint8_t byte_value,
     libsigscan_scan_object_t **scan_object,
     libcerror_error_t **error );

int libsigscan_scan_tree_node_scan_buffer(
     libsigscan_scan_tree_node_t *scan_tree_node,
     int pattern_offsets_mode,
     off64_t data_offset,
     size64_t data_size,
     const uint8_t *buffer,
     size_t buffer_size,
     size_t buffer_offset,
     libsigscan_scan_object_t **scan_object,
     libcerror_error_t **error );

#if defined( HAVE_DEBUG_OUTPUT )

int libsigscan_scan_tree_node_printf(
     libsigscan_scan_tree_node_t *scan_tree_node,
     libcerror_error_t **error );

#endif /* defined( HAVE_DEBUG_OUTPUT ) */

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_SCAN_TREE_NODE_H ) */

