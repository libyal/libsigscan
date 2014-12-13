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

#if !defined( _LIBSIGSCAN_DEBUG_H )
#define _LIBSIGSCAN_DEBUG_H

#include <common.h>
#include <types.h>

#include "libsigscan_libcerror.h"
#include "libsigscan_skip_table.h"

#if defined( __cplusplus )
extern "C" {
#endif

#if defined( HAVE_DEBUG_OUTPUT )

int libsigscan_debug_print_skip_table(
     libsigscan_skip_table_t *skip_table,
     libcerror_error_t **error );

#endif

#if defined( __cplusplus )
}
#endif

#endif

