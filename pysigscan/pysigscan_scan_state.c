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

#include <common.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pysigscan_error.h"
#include "pysigscan_libcerror.h"
#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"
#include "pysigscan_scan_result.h"
#include "pysigscan_scan_results.h"
#include "pysigscan_scan_state.h"
#include "pysigscan_unused.h"

PyMethodDef pysigscan_scan_state_object_methods[] = {

	{ "set_data_size",
	  (PyCFunction) pysigscan_scan_state_set_data_size,
	  METH_VARARGS | METH_KEYWORDS,
	  "set_data_size(data_size) -> None\n"
	  "\n"
	  "Set the size of the data." },

	/* Functions to access the scan results */

	{ "get_number_of_scan_results",
	  (PyCFunction) pysigscan_scan_state_get_number_of_scan_results,
	  METH_NOARGS,
	  "get_number_of_scan_results() -> Integer\n"
	  "\n"
	  "Retrieves the number of scan results." },

	{ "get_scan_result",
	  (PyCFunction) pysigscan_scan_state_get_scan_result,
	  METH_VARARGS | METH_KEYWORDS,
	  "get_scan_result(result_index) -> Object or None\n"
	  "\n"
	  "Retrieves a specific scan result." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

PyGetSetDef pysigscan_scan_state_object_get_set_definitions[] = {

	{ "number_of_scan_results",
	  (getter) pysigscan_scan_state_get_number_of_scan_results,
	  (setter) 0,
	  "The number of scan results.",
	  NULL },

	{ "scan_results",
	  (getter) pysigscan_scan_state_get_scan_results,
	  (setter) 0,
	  "The scan results",
	  NULL },

	/* Sentinel */
	{ NULL, NULL, NULL, NULL, NULL }
};

PyTypeObject pysigscan_scan_state_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pysigscan.scan_state",
	/* tp_basicsize */
	sizeof( pysigscan_scan_state_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pysigscan_scan_state_free,
	/* tp_print */
	0,
	/* tp_getattr */
	0,
	/* tp_setattr */
	0,
	/* tp_compare */
	0,
	/* tp_repr */
	0,
	/* tp_as_number */
	0,
	/* tp_as_sequence */
	0,
	/* tp_as_mapping */
	0,
	/* tp_hash */
	0,
	/* tp_call */
	0,
	/* tp_str */
	0,
	/* tp_getattro */
	0,
	/* tp_setattro */
	0,
	/* tp_as_buffer */
	0,
	/* tp_flags */
	Py_TPFLAGS_DEFAULT,
	/* tp_doc */
	"pysigscan scan state object (wraps libsigscan_scan_state_t)",
	/* tp_traverse */
	0,
	/* tp_clear */
	0,
	/* tp_richcompare */
	0,
	/* tp_weaklistoffset */
	0,
	/* tp_iter */
	0,
	/* tp_iternext */
	0,
	/* tp_methods */
	pysigscan_scan_state_object_methods,
	/* tp_members */
	0,
	/* tp_getset */
	pysigscan_scan_state_object_get_set_definitions,
	/* tp_base */
	0,
	/* tp_dict */
	0,
	/* tp_descr_get */
	0,
	/* tp_descr_set */
	0,
	/* tp_dictoffset */
	0,
	/* tp_init */
	(initproc) pysigscan_scan_state_init,
	/* tp_alloc */
	0,
	/* tp_new */
	0,
	/* tp_free */
	0,
	/* tp_is_gc */
	0,
	/* tp_bases */
	NULL,
	/* tp_mro */
	NULL,
	/* tp_cache */
	NULL,
	/* tp_subclasses */
	NULL,
	/* tp_weaklist */
	NULL,
	/* tp_del */
	0
};

/* Creates a new scan state object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_state_new(
           void )
{
	pysigscan_scan_state_t *pysigscan_scan_state = NULL;
	static char *function                        = "pysigscan_scan_state_new";

	pysigscan_scan_state = PyObject_New(
	                        struct pysigscan_scan_state,
	                        &pysigscan_scan_state_type_object );

	if( pysigscan_scan_state == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize scan state.",
		 function );

		goto on_error;
	}
	if( pysigscan_scan_state_init(
	     pysigscan_scan_state ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize scan state.",
		 function );

		goto on_error;
	}
	return( (PyObject *) pysigscan_scan_state );

on_error:
	if( pysigscan_scan_state != NULL )
	{
		Py_DecRef(
		 (PyObject *) pysigscan_scan_state );
	}
	return( NULL );
}

/* Intializes a scan state object
 * Returns 0 if successful or -1 on error
 */
int pysigscan_scan_state_init(
     pysigscan_scan_state_t *pysigscan_scan_state )
{
	static char *function    = "pysigscan_scan_state_init";
	libcerror_error_t *error = NULL;

	if( pysigscan_scan_state == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan state.",
		 function );

		return( -1 );
	}
	pysigscan_scan_state->scan_state = NULL;

	if( libsigscan_scan_state_initialize(
	     &( pysigscan_scan_state->scan_state ),
	     &error ) != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to initialize scan state.",
		 function );

		libcerror_error_free(
		 &error );

		return( -1 );
	}
	return( 0 );
}

/* Frees a scan state object
 */
void pysigscan_scan_state_free(
      pysigscan_scan_state_t *pysigscan_scan_state )
{
	libcerror_error_t *error    = NULL;
	struct _typeobject *ob_type = NULL;
	static char *function       = "pysigscan_scan_state_free";
	int result                  = 0;

	if( pysigscan_scan_state == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan state.",
		 function );

		return;
	}
	if( pysigscan_scan_state->scan_state == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan state - missing libsigscan scan state.",
		 function );

		return;
	}
	ob_type = Py_TYPE(
	           pysigscan_scan_state );

	if( ob_type == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: missing ob_type.",
		 function );

		return;
	}
	if( ob_type->tp_free == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid ob_type - missing tp_free.",
		 function );

		return;
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scan_state_free(
	          &( pysigscan_scan_state->scan_state ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to free libsigscan scan state.",
		 function );

		libcerror_error_free(
		 &error );
	}
	ob_type->tp_free(
	 (PyObject*) pysigscan_scan_state );
}

/* Sets the size of the data
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_state_set_data_size(
           pysigscan_scan_state_t *pysigscan_scan_state,
           PyObject *arguments,
           PyObject *keywords )
{
	libcerror_error_t *error    = NULL;
	static char *function       = "pysigscan_scan_state_set_data_size";
	static char *keyword_list[] = { "data_size", NULL };
	size64_t data_size          = 0;
	int result                  = 0;

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "L",
	     keyword_list,
	     &data_size ) == 0 )
	{
		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scan_state_set_data_size(
	          pysigscan_scan_state->scan_state,
	          data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to set data size.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

/* Retrieves the number of scan results
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_state_get_number_of_scan_results(
           pysigscan_scan_state_t *pysigscan_scan_state,
           PyObject *arguments PYSIGSCAN_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error = NULL;
	PyObject *integer_object = NULL;
	static char *function    = "pysigscan_scan_state_get_number_of_scan_results";
	int number_of_results    = 0;
	int result               = 0;

	PYSIGSCAN_UNREFERENCED_PARAMETER( arguments )

	if( pysigscan_scan_state == NULL )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: invalid scan state.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scan_state_get_number_of_results(
	          pysigscan_scan_state->scan_state,
	          &number_of_results,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to retrieve number of scan results.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	integer_object = PyLong_FromLong(
	                  (long) number_of_results );
#else
	integer_object = PyInt_FromLong(
	                  (long) number_of_results );
#endif
	return( integer_object );
}

/* Retrieves a specific scan result by index
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_state_get_scan_result_by_index(
           PyObject *pysigscan_scan_state,
           int result_index )
{
	libcerror_error_t *error              = NULL;
	libsigscan_scan_result_t *scan_result = NULL;
	PyObject *scan_result_object          = NULL;
	static char *function                 = "pysigscan_scan_state_get_scan_result_by_index";
	int result                            = 0;

	if( pysigscan_scan_state == NULL )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: invalid scan state.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scan_state_get_result(
	          ( (pysigscan_scan_state_t *) pysigscan_scan_state )->scan_state,
	          result_index,
	          &scan_result,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to retrieve scan result: %d.",
		 function,
		 result_index );

		libcerror_error_free(
		 &error );

		goto on_error;
	}
	scan_result_object = pysigscan_scan_result_new(
	                      scan_result,
	                      (pysigscan_scan_state_t *) pysigscan_scan_state );

	if( scan_result_object == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to create scan result object.",
		 function );

		goto on_error;
	}
	return( scan_result_object );

on_error:
	if( scan_result != NULL )
	{
		libsigscan_scan_result_free(
		 &scan_result,
		 NULL );
	}
	return( NULL );
}

/* Retrieves a specific scan result
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_state_get_scan_result(
           pysigscan_scan_state_t *pysigscan_scan_state,
           PyObject *arguments,
           PyObject *keywords )
{
	PyObject *scan_result_object = NULL;
	static char *keyword_list[]  = { "result_index", NULL };
	int result_index             = 0;

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "i",
	     keyword_list,
	     &result_index ) == 0 )
	{
		return( NULL );
	}
	scan_result_object = pysigscan_scan_state_get_scan_result_by_index(
	                      (PyObject *) pysigscan_scan_state,
	                      result_index );

	return( scan_result_object );
}

/* Retrieves a scan results sequence and iterator object for the scan results
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_state_get_scan_results(
           pysigscan_scan_state_t *pysigscan_scan_state,
           PyObject *arguments PYSIGSCAN_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error      = NULL;
	PyObject *scan_results_object = NULL;
	static char *function         = "pysigscan_scan_state_get_scan_results";
	int number_of_results         = 0;
	int result                    = 0;

	PYSIGSCAN_UNREFERENCED_PARAMETER( arguments )

	if( pysigscan_scan_state == NULL )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: invalid scan state.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scan_state_get_number_of_results(
	          pysigscan_scan_state->scan_state,
	          &number_of_results,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to retrieve number of scan results.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	scan_results_object = pysigscan_scan_results_new(
	                       (PyObject *) pysigscan_scan_state,
	                       &pysigscan_scan_state_get_scan_result_by_index,
	                       number_of_results );

	if( scan_results_object == NULL )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to create scan results object.",
		 function );

		return( NULL );
	}
	return( scan_results_object );
}

