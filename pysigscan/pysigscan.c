/*
 * Python bindings module for libsigscan (pysigscan)
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

#include <common.h>
#include <narrow_string.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pysigscan.h"
#include "pysigscan_error.h"
#include "pysigscan_libcerror.h"
#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"
#include "pysigscan_scan_result.h"
#include "pysigscan_scan_results.h"
#include "pysigscan_scan_state.h"
#include "pysigscan_scanner.h"
#include "pysigscan_signature_flags.h"
#include "pysigscan_unused.h"

/* The pysigscan module methods
 */
PyMethodDef pysigscan_module_methods[] = {
	{ "get_version",
	  (PyCFunction) pysigscan_get_version,
	  METH_NOARGS,
	  "get_version() -> String\n"
	  "\n"
	  "Retrieves the version." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

/* Retrieves the pysigscan/libsigscan version
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_get_version(
           PyObject *self PYSIGSCAN_ATTRIBUTE_UNUSED,
           PyObject *arguments PYSIGSCAN_ATTRIBUTE_UNUSED )
{
	const char *errors           = NULL;
	const char *version_string   = NULL;
	size_t version_string_length = 0;

	PYSIGSCAN_UNREFERENCED_PARAMETER( self )
	PYSIGSCAN_UNREFERENCED_PARAMETER( arguments )

	Py_BEGIN_ALLOW_THREADS

	version_string = libsigscan_get_version();

	Py_END_ALLOW_THREADS

	version_string_length = narrow_string_length(
	                         version_string );

	/* Pass the string length to PyUnicode_DecodeUTF8
	 * otherwise it makes the end of string character is part
	 * of the string
	 */
	return( PyUnicode_DecodeUTF8(
	         version_string,
	         (Py_ssize_t) version_string_length,
	         errors ) );
}

#if PY_MAJOR_VERSION >= 3

/* The pysigscan module definition
 */
PyModuleDef pysigscan_module_definition = {
	PyModuleDef_HEAD_INIT,

	/* m_name */
	"pysigscan",
	/* m_doc */
	"Python libsigscan module (pysigscan).",
	/* m_size */
	-1,
	/* m_methods */
	pysigscan_module_methods,
	/* m_reload */
	NULL,
	/* m_traverse */
	NULL,
	/* m_clear */
	NULL,
	/* m_free */
	NULL,
};

#endif /* PY_MAJOR_VERSION >= 3 */

/* Initializes the pysigscan module
 */
#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_pysigscan(
                void )
#else
PyMODINIT_FUNC initpysigscan(
                void )
#endif
{
	PyObject *module           = NULL;
	PyGILState_STATE gil_state = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	libsigscan_notify_set_stream(
	 stderr,
	 NULL );
	libsigscan_notify_set_verbose(
	 1 );
#endif

	/* Create the module
	 * This function must be called before grabbing the GIL
	 * otherwise the module will segfault on a version mismatch
	 */
#if PY_MAJOR_VERSION >= 3
	module = PyModule_Create(
	          &pysigscan_module_definition );
#else
	module = Py_InitModule3(
	          "pysigscan",
	          pysigscan_module_methods,
	          "Python libsigscan module (pysigscan)." );
#endif
	if( module == NULL )
	{
#if PY_MAJOR_VERSION >= 3
		return( NULL );
#else
		return;
#endif
	}
#if PY_VERSION_HEX < 0x03070000
	PyEval_InitThreads();
#endif
	gil_state = PyGILState_Ensure();

	/* Setup the scan_result type object
	 */
	pysigscan_scan_result_type_object.tp_new = PyType_GenericNew;

	if( PyType_Ready(
	     &pysigscan_scan_result_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pysigscan_scan_result_type_object );

	PyModule_AddObject(
	 module,
	 "scan_result",
	 (PyObject *) &pysigscan_scan_result_type_object );

	/* Setup the scan_results type object
	 */
	pysigscan_scan_results_type_object.tp_new = PyType_GenericNew;

	if( PyType_Ready(
	     &pysigscan_scan_results_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pysigscan_scan_results_type_object );

	PyModule_AddObject(
	 module,
	 "scan_results",
	 (PyObject *) &pysigscan_scan_results_type_object );

	/* Setup the scan_state type object
	 */
	pysigscan_scan_state_type_object.tp_new = PyType_GenericNew;

	if( PyType_Ready(
	     &pysigscan_scan_state_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pysigscan_scan_state_type_object );

	PyModule_AddObject(
	 module,
	 "scan_state",
	 (PyObject *) &pysigscan_scan_state_type_object );

	/* Setup the scanner type object
	 */
	pysigscan_scanner_type_object.tp_new = PyType_GenericNew;

	if( PyType_Ready(
	     &pysigscan_scanner_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pysigscan_scanner_type_object );

	PyModule_AddObject(
	 module,
	 "scanner",
	 (PyObject *) &pysigscan_scanner_type_object );

	/* Setup the signature_flags type object
	 */
	pysigscan_signature_flags_type_object.tp_new = PyType_GenericNew;

	if( pysigscan_signature_flags_init_type(
	     &pysigscan_signature_flags_type_object ) != 1 )
	{
		goto on_error;
	}
	if( PyType_Ready(
	     &pysigscan_signature_flags_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pysigscan_signature_flags_type_object );

	PyModule_AddObject(
	 module,
	 "signature_flags",
	 (PyObject *) &pysigscan_signature_flags_type_object );

	PyGILState_Release(
	 gil_state );

#if PY_MAJOR_VERSION >= 3
	return( module );
#else
	return;
#endif

on_error:
	PyGILState_Release(
	 gil_state );

#if PY_MAJOR_VERSION >= 3
	return( NULL );
#else
	return;
#endif
}

