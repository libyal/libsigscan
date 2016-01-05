/*
 * Python object definition of the scan results sequence and iterator
 *
 * Copyright (C) 2014-2016, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _PYSIGSCAN_SCAN_RESULTS_H )
#define _PYSIGSCAN_SCAN_RESULTS_H

#include <common.h>
#include <types.h>

#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"
#include "pysigscan_scan_state.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pysigscan_scan_results pysigscan_scan_results_t;

struct pysigscan_scan_results
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The scan state object
	 */
	pysigscan_scan_state_t *scan_state_object;

	/* The get scan result by index callback function
	 */
	PyObject* (*get_scan_result_by_index)(
	             pysigscan_scan_state_t *scan_state_object,
	             int result_index );

	/* The (current) (scan) result index
	 */
	int result_index;

	/* The number of (scan) results
	 */
	int number_of_results;
};

extern PyTypeObject pysigscan_scan_results_type_object;

PyObject *pysigscan_scan_results_new(
           pysigscan_scan_state_t *scan_state_object,
           PyObject* (*get_scan_result_by_index)(
                        pysigscan_scan_state_t *scan_state_object,
                        int result_index ),
           int number_of_results );

int pysigscan_scan_results_init(
     pysigscan_scan_results_t *pysigscan_scan_results );

void pysigscan_scan_results_free(
      pysigscan_scan_results_t *pysigscan_scan_results );

Py_ssize_t pysigscan_scan_results_len(
            pysigscan_scan_results_t *pysigscan_scan_results );

PyObject *pysigscan_scan_results_getitem(
           pysigscan_scan_results_t *pysigscan_scan_results,
           Py_ssize_t item_index );

PyObject *pysigscan_scan_results_iter(
           pysigscan_scan_results_t *pysigscan_scan_results );

PyObject *pysigscan_scan_results_iternext(
           pysigscan_scan_results_t *pysigscan_scan_results );

#if defined( __cplusplus )
}
#endif

#endif

