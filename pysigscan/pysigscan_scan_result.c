/*
 * Python object wrapper of libsigscan_scan_result_t
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pysigscan_error.h"
#include "pysigscan_libcerror.h"
#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"
#include "pysigscan_scan_result.h"
#include "pysigscan_scan_state.h"
#include "pysigscan_unused.h"

PyMethodDef pysigscan_scan_result_object_methods[] = {

	{ "get_identifier",
	  (PyCFunction) pysigscan_scan_result_get_identifier,
	  METH_NOARGS,
	  "get_identifier() -> Unicode string or None\n"
	  "\n"
	  "Retrieves the identifier." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

PyGetSetDef pysigscan_scan_result_object_get_set_definitions[] = {

	{ "identifier",
	  (getter) pysigscan_scan_result_get_identifier,
	  (setter) 0,
	  "The identifier.",
	  NULL },

	/* Sentinel */
	{ NULL, NULL, NULL, NULL, NULL }
};

PyTypeObject pysigscan_scan_result_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pysigscan.scan_result",
	/* tp_basicsize */
	sizeof( pysigscan_scan_result_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pysigscan_scan_result_free,
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
	"pysigscan scan result object (wraps libsigscan_scan_result_t)",
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
	pysigscan_scan_result_object_methods,
	/* tp_members */
	0,
	/* tp_getset */
	pysigscan_scan_result_object_get_set_definitions,
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
	(initproc) pysigscan_scan_result_init,
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

/* Creates a new scan result object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_result_new(
           libsigscan_scan_result_t *scan_result,
           pysigscan_scan_state_t *scan_state_object )
{
	pysigscan_scan_result_t *pysigscan_scan_result = NULL;
	static char *function                          = "pysigscan_scan_result_new";

	if( scan_result == NULL )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: invalid scan result.",
		 function );

		return( NULL );
	}
	pysigscan_scan_result = PyObject_New(
	                         struct pysigscan_scan_result,
	                         &pysigscan_scan_result_type_object );

	if( pysigscan_scan_result == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize scan result.",
		 function );

		goto on_error;
	}
	if( pysigscan_scan_result_init(
	     pysigscan_scan_result ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize scan result.",
		 function );

		goto on_error;
	}
	pysigscan_scan_result->scan_result       = scan_result;
	pysigscan_scan_result->scan_state_object = scan_state_object;

	Py_IncRef(
	 (PyObject *) pysigscan_scan_result->scan_state_object );

	return( (PyObject *) pysigscan_scan_result );

on_error:
	if( pysigscan_scan_result != NULL )
	{
		Py_DecRef(
		 (PyObject *) pysigscan_scan_result );
	}
	return( NULL );
}

/* Initializes a scan result object
 * Returns 0 if successful or -1 on error
 */
int pysigscan_scan_result_init(
     pysigscan_scan_result_t *pysigscan_scan_result )
{
	static char *function = "pysigscan_scan_result_init";

	if( pysigscan_scan_result == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan result.",
		 function );

		return( -1 );
	}
	/* Make sure libsigscan scan result is set to NULL
	 */
	pysigscan_scan_result->scan_result = NULL;

	return( 0 );
}

/* Frees a scan result object
 */
void pysigscan_scan_result_free(
      pysigscan_scan_result_t *pysigscan_scan_result )
{
	libcerror_error_t *error    = NULL;
	struct _typeobject *ob_type = NULL;
	static char *function       = "pysigscan_scan_result_free";
	int result                  = 0;

	if( pysigscan_scan_result == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan result.",
		 function );

		return;
	}
	if( pysigscan_scan_result->scan_result == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan result - missing libsigscan scan result.",
		 function );

		return;
	}
	ob_type = Py_TYPE(
	           pysigscan_scan_result );

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

	result = libsigscan_scan_result_free(
	          &( pysigscan_scan_result->scan_result ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to free libsigscan scan result.",
		 function );

		libcerror_error_free(
		 &error );
	}
	if( pysigscan_scan_result->scan_state_object != NULL )
	{
		Py_DecRef(
		 (PyObject *) pysigscan_scan_result->scan_state_object );
	}
	ob_type->tp_free(
	 (PyObject*) pysigscan_scan_result );
}

/* Retrieves the identifier
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_result_get_identifier(
           pysigscan_scan_result_t *pysigscan_scan_result,
           PyObject *arguments PYSIGSCAN_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error = NULL;
	PyObject *string_object  = NULL;
	const char *errors       = NULL;
	char *identifier         = NULL;
	static char *function    = "pysigscan_scan_result_get_identifier";
	size_t identifier_size   = 0;
	int result               = 0;

	PYSIGSCAN_UNREFERENCED_PARAMETER( arguments )

	if( pysigscan_scan_result == NULL )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: invalid scan result.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scan_result_get_identifier_size(
	          pysigscan_scan_result->scan_result,
	          &identifier_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result == -1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to retrieve identifier size.",
		 function );

		libcerror_error_free(
		 &error );

		goto on_error;
	}
	else if( ( result == 0 )
	      || ( identifier_size == 0 ) )
	{
		Py_IncRef(
		 Py_None );

		return( Py_None );
	}
	identifier = (char *) PyMem_Malloc(
	                       sizeof( char ) * identifier_size );

	if( identifier == NULL )
	{
		PyErr_Format(
		 PyExc_IOError,
		 "%s: unable to create identifier.",
		 function );

		goto on_error;
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scan_result_get_identifier(
		  pysigscan_scan_result->scan_result,
		  identifier,
		  identifier_size,
		  &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to retrieve identifier.",
		 function );

		libcerror_error_free(
		 &error );

		goto on_error;
	}
	/* Pass the string length to PyUnicode_DecodeUTF8
	 * otherwise it makes the end of string character is part
	 * of the string
	 */
	string_object = PyUnicode_DecodeUTF8(
			 identifier,
			 (Py_ssize_t) identifier_size - 1,
			 errors );

	PyMem_Free(
	 identifier );

	return( string_object );

on_error:
	if( identifier != NULL )
	{
		PyMem_Free(
		 identifier );
	}
	return( NULL );
}

