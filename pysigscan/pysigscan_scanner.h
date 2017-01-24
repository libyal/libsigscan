/*
 * Python object definition of the libsigscan scanner
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

#if !defined( _PYSIGSCAN_SCANNER_H )
#define _PYSIGSCAN_SCANNER_H

#include <common.h>
#include <types.h>

#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pysigscan_scanner pysigscan_scanner_t;

struct pysigscan_scanner
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The libsigscan scanner
	 */
	libsigscan_scanner_t *scanner;
};

extern PyMethodDef pysigscan_scanner_object_methods[];
extern PyTypeObject pysigscan_scanner_type_object;

PyObject *pysigscan_scanner_new(
           void );

int pysigscan_scanner_init(
     pysigscan_scanner_t *pysigscan_scanner );

void pysigscan_scanner_free(
      pysigscan_scanner_t *pysigscan_scanner );

PyObject *pysigscan_scanner_signal_abort(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments );

PyObject *pysigscan_scanner_set_scan_buffer_size(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pysigscan_scanner_add_signature(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pysigscan_scanner_scan_start(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pysigscan_scanner_scan_stop(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pysigscan_scanner_scan_buffer(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pysigscan_scanner_scan_file(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pysigscan_scanner_scan_file_object(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords );

#if defined( __cplusplus )
}
#endif

#endif

