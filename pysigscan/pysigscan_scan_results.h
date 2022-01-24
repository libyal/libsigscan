/*
 * Python object definition of the sequence and iterator object of scan results
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

#if !defined( _PYSIGSCAN_SCAN_RESULTS_H )
#define _PYSIGSCAN_SCAN_RESULTS_H

#include <common.h>
#include <types.h>

#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pysigscan_scan_results pysigscan_scan_results_t;

struct pysigscan_scan_results
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The parent object
	 */
	PyObject *parent_object;

	/* The get item by index callback function
	 */
	PyObject* (*get_item_by_index)(
	             PyObject *parent_object,
	             int index );

	/* The current index
	 */
	int current_index;

	/* The number of items
	 */
	int number_of_items;
};

extern PyTypeObject pysigscan_scan_results_type_object;

PyObject *pysigscan_scan_results_new(
           PyObject *parent_object,
           PyObject* (*get_item_by_index)(
                        PyObject *parent_object,
                        int index ),
           int number_of_items );

int pysigscan_scan_results_init(
     pysigscan_scan_results_t *sequence_object );

void pysigscan_scan_results_free(
      pysigscan_scan_results_t *sequence_object );

Py_ssize_t pysigscan_scan_results_len(
            pysigscan_scan_results_t *sequence_object );

PyObject *pysigscan_scan_results_getitem(
           pysigscan_scan_results_t *sequence_object,
           Py_ssize_t item_index );

PyObject *pysigscan_scan_results_iter(
           pysigscan_scan_results_t *sequence_object );

PyObject *pysigscan_scan_results_iternext(
           pysigscan_scan_results_t *sequence_object );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _PYSIGSCAN_SCAN_RESULTS_H ) */

