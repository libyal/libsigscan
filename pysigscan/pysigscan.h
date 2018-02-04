/*
 * Python bindings for libsigscan (pysigscan)
 *
 * Copyright (C) 2014-2018, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _PYSIGSCAN_H )
#define _PYSIGSCAN_H

#include <common.h>
#include <types.h>

#include "pysigscan_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

PyObject *pysigscan_get_version(
           PyObject *self,
           PyObject *arguments );

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_pysigscan(
                void );
#else
PyMODINIT_FUNC initpysigscan(
                void );
#endif

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _PYSIGSCAN_H ) */

