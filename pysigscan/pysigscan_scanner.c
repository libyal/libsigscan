/*
 * Python object definition of the libsigscan scanner
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

#include <common.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pysigscan_error.h"
#include "pysigscan_file_object_io_handle.h"
#include "pysigscan_libbfio.h"
#include "pysigscan_libcerror.h"
#include "pysigscan_libclocale.h"
#include "pysigscan_libcstring.h"
#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"
#include "pysigscan_scanner.h"
#include "pysigscan_unused.h"

PyMethodDef pysigscan_scanner_object_methods[] = {

	{ "signal_abort",
	  (PyCFunction) pysigscan_scanner_signal_abort,
	  METH_NOARGS,
	  "signal_abort() -> None\n"
	  "\n"
	  "Signals the scanner to abort the current activity." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

PyGetSetDef pysigscan_scanner_object_get_set_definitions[] = {

	/* Sentinel */
	{ NULL, NULL, NULL, NULL, NULL }
};

PyTypeObject pysigscan_scanner_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pysigscan.scanner",
	/* tp_basicsize */
	sizeof( pysigscan_scanner_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pysigscan_scanner_free,
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
	"pysigscan scanner object (wraps libsigscan_scanner_t)",
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
	pysigscan_scanner_object_methods,
	/* tp_members */
	0,
	/* tp_getset */
	pysigscan_scanner_object_get_set_definitions,
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
	(initproc) pysigscan_scanner_init,
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

/* Creates a new scanner object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_new(
           void )
{
	pysigscan_scanner_t *pysigscan_scanner = NULL;
	static char *function                  = "pysigscan_scanner_new";

	pysigscan_scanner = PyObject_New(
	                     struct pysigscan_scanner,
	                     &pysigscan_scanner_type_object );

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize scanner.",
		 function );

		goto on_error;
	}
	if( pysigscan_scanner_init(
	     pysigscan_scanner ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize scanner.",
		 function );

		goto on_error;
	}
	return( (PyObject *) pysigscan_scanner );

on_error:
	if( pysigscan_scanner != NULL )
	{
		Py_DecRef(
		 (PyObject *) pysigscan_scanner );
	}
	return( NULL );
}

/* Intializes a scanner object
 * Returns 0 if successful or -1 on error
 */
int pysigscan_scanner_init(
     pysigscan_scanner_t *pysigscan_scanner )
{
	static char *function    = "pysigscan_scanner_init";
	libcerror_error_t *error = NULL;

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return( -1 );
	}
	pysigscan_scanner->scanner        = NULL;
	pysigscan_scanner->file_io_handle = NULL;

	if( libsigscan_scanner_initialize(
	     &( pysigscan_scanner->scanner ),
	     &error ) != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to initialize scanner.",
		 function );

		libcerror_error_free(
		 &error );

		return( -1 );
	}
	return( 0 );
}

/* Frees a scanner object
 */
void pysigscan_scanner_free(
      pysigscan_scanner_t *pysigscan_scanner )
{
	libcerror_error_t *error    = NULL;
	struct _typeobject *ob_type = NULL;
	static char *function       = "pysigscan_scanner_free";
	int result                  = 0;

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return;
	}
	ob_type = Py_TYPE( pysigscan_scanner );

	if( ob_type == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner - missing ob_type.",
		 function );

		return;
	}
	if( ob_type->tp_free == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner - invalid ob_type - missing tp_free.",
		 function );

		return;
	}
	if( pysigscan_scanner->scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner - missing libsigscan scanner.",
		 function );

		return;
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scanner_free(
	          &( pysigscan_scanner->scanner ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to free libsigscan scanner.",
		 function );

		libcerror_error_free(
		 &error );
	}
	ob_type->tp_free(
	 (PyObject*) pysigscan_scanner );
}

/* Signals the scanner to abort the current activity
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_signal_abort(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments PYSIGSCAN_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error = NULL;
	static char *function    = "pysigscan_scanner_signal_abort";
	int result               = 0;

	PYSIGSCAN_UNREFERENCED_PARAMETER( arguments )

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scanner_signal_abort(
	          pysigscan_scanner->scanner,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to signal abort.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

