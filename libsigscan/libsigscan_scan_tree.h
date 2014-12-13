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

#if !defined( _LIBSIGSCAN_SCAN_TREE_H )
#define _LIBSIGSCAN_SCAN_TREE_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcdata.h"
#include "libsigscan_libcerror.h"
#include "libsigscan_signature_table.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libsigscan_scan_tree libsigscan_scan_tree_t;

struct libsigscan_scan_tree
{
	/* The root tree node
	 */
	libcdata_tree_node_t *root_node;
};

int libsigscan_scan_tree_initialize(
     libsigscan_scan_tree_t **scan_tree,
     libcerror_error_t **error );

int libsigscan_scan_tree_free(
     libsigscan_scan_tree_t **scan_tree,
     libcerror_error_t **error );

int libsigscan_scan_tree_build_node(
     libsigscan_scan_tree_t *scan_tree,
     libsigscan_signature_table_t *signature_table,
     libcdata_tree_node_t **tree_node,
     libcerror_error_t **error );

int libsigscan_scan_tree_build(
     libsigscan_scan_tree_t *scan_tree,
     libcdata_array_t *signatures_array,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif

