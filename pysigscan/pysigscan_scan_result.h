/*
 * Python object definition of the libsigscan scan result
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

#if !defined( _PYSIGSCAN_SCAN_RESULT_H )
#define _PYSIGSCAN_SCAN_RESULT_H

#include <common.h>
#include <types.h>

#include "pysigscan_libbfio.h"
#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"
#include "pysigscan_scan_state.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pysigscan_scan_result pysigscan_scan_result_t;

struct pysigscan_scan_result
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The libsigscan scan result
	 */
	libsigscan_scan_result_t *scan_result;

	/* The scan state object
	 */
	pysigscan_scan_state_t *scan_state_object;
};

extern PyMethodDef pysigscan_scan_result_object_methods[];
extern PyTypeObject pysigscan_scan_result_type_object;

PyObject *pysigscan_scan_result_new(
           libsigscan_scan_result_t *scan_result,
           pysigscan_scan_state_t *scan_state_object );

int pysigscan_scan_result_init(
     pysigscan_scan_result_t *pysigscan_scan_result );

void pysigscan_scan_result_free(
      pysigscan_scan_result_t *pysigscan_scan_result );

PyObject *pysigscan_scan_result_get_identifier(
           pysigscan_scan_result_t *pysigscan_scan_result,
           PyObject *arguments );

#if defined( __cplusplus )
}
#endif

#endif

