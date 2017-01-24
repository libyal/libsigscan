/*
 * Python object definition of the libsigscan scan state
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

#if !defined( _PYSIGSCAN_SCAN_STATE_H )
#define _PYSIGSCAN_SCAN_STATE_H

#include <common.h>
#include <types.h>

#include "pysigscan_libbfio.h"
#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pysigscan_scan_state pysigscan_scan_state_t;

struct pysigscan_scan_state
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The libsigscan scan state
	 */
	libsigscan_scan_state_t *scan_state;
};

extern PyMethodDef pysigscan_scan_state_object_methods[];
extern PyTypeObject pysigscan_scan_state_type_object;

PyObject *pysigscan_scan_state_new(
           void );

int pysigscan_scan_state_init(
     pysigscan_scan_state_t *pysigscan_scan_state );

void pysigscan_scan_state_free(
      pysigscan_scan_state_t *pysigscan_scan_state );

PyObject *pysigscan_scan_state_set_data_size(
           pysigscan_scan_state_t *pysigscan_scan_state,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pysigscan_scan_state_get_number_of_scan_results(
           pysigscan_scan_state_t *pysigscan_scan_state,
           PyObject *arguments );

PyObject *pysigscan_scan_state_get_scan_result_by_index(
           PyObject *pysigscan_scan_state,
           int result_index );

PyObject *pysigscan_scan_state_get_scan_result(
           pysigscan_scan_state_t *pysigscan_scan_state,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pysigscan_scan_state_get_scan_results(
           pysigscan_scan_state_t *pysigscan_scan_state,
           PyObject *arguments );

#if defined( __cplusplus )
}
#endif

#endif

