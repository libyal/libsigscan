/*
 * Python object wrapper of libsigscan_scanner_t
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
#include "pysigscan_file_object_io_handle.h"
#include "pysigscan_libbfio.h"
#include "pysigscan_libcerror.h"
#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"
#include "pysigscan_scanner.h"
#include "pysigscan_scan_state.h"
#include "pysigscan_unused.h"

#if !defined( LIBSIGSCAN_HAVE_BFIO )

LIBSIGSCAN_EXTERN \
int libsigscan_scanner_scan_file_io_handle(
     libsigscan_scanner_t *scanner,
     libsigscan_scan_state_t *scan_state,
     libbfio_handle_t *file_io_handle,
     libsigscan_error_t **error );

#endif /* !defined( LIBSIGSCAN_HAVE_BFIO ) */

PyMethodDef pysigscan_scanner_object_methods[] = {

	{ "signal_abort",
	  (PyCFunction) pysigscan_scanner_signal_abort,
	  METH_NOARGS,
	  "signal_abort() -> None\n"
	  "\n"
	  "Signals the scanner to abort the current activity." },

	{ "set_scan_buffer_size",
	  (PyCFunction) pysigscan_scanner_set_scan_buffer_size,
	  METH_VARARGS | METH_KEYWORDS,
	  "set_scan_buffer_size(buffer_size) -> None\n"
	  "\n"
	  "Set the size of the scan buffer." },

	/* Functions to access signatures */

	{ "add_signature",
	  (PyCFunction) pysigscan_scanner_add_signature,
	  METH_VARARGS | METH_KEYWORDS,
	  "add_signature(identifier, pattern_offset, pattern, signature_flags) -> None\n"
	  "\n"
	  "Adds a signature." },

	/* Functions for scanning */

	{ "scan_start",
	  (PyCFunction) pysigscan_scanner_scan_start,
	  METH_VARARGS | METH_KEYWORDS,
	  "scan_start(scan_state) -> None\n"
	  "\n"
	  "Starts the scan." },

	{ "scan_stop",
	  (PyCFunction) pysigscan_scanner_scan_stop,
	  METH_VARARGS | METH_KEYWORDS,
	  "scan_stop(scan_state) -> None\n"
	  "\n"
	  "Stops the scan." },

	{ "scan_buffer",
	  (PyCFunction) pysigscan_scanner_scan_buffer,
	  METH_VARARGS | METH_KEYWORDS,
	  "scan_buffer(scan_state, buffer) -> None\n"
	  "\n"
	  "Scans the buffer." },

	{ "scan_file",
	  (PyCFunction) pysigscan_scanner_scan_file,
	  METH_VARARGS | METH_KEYWORDS,
	  "scan_file(scan_state, filename) -> None\n"
	  "\n"
	  "Scans a file." },

	{ "scan_file_object",
	  (PyCFunction) pysigscan_scanner_scan_file_object,
	  METH_VARARGS | METH_KEYWORDS,
	  "scan_file_object(scan_state, file_object) -> None\n"
	  "\n"
	  "Scans a file using a file-like object." },

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

/* Initializes a scanner object
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
	pysigscan_scanner->scanner = NULL;

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
	if( pysigscan_scanner->scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner - missing libsigscan scanner.",
		 function );

		return;
	}
	ob_type = Py_TYPE(
	           pysigscan_scanner );

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

/* Sets the size of the scan buffer
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_set_scan_buffer_size(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords )
{
	libcerror_error_t *error    = NULL;
	static char *function       = "pysigscan_scanner_set_scan_buffer_size";
	static char *keyword_list[] = { "buffer_size", NULL };
	Py_ssize_t buffer_size      = 0;
	int result                  = 0;

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "n",
	     keyword_list,
	     &buffer_size ) == 0 )
	{
		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scanner_set_scan_buffer_size(
	          pysigscan_scanner->scanner,
	          (size_t) buffer_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to set scan buffer size.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

/* Adds a signature
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_add_signature(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords )
{
	PyObject *string_object      = NULL;
	PyObject *utf8_string_object = NULL;
	libcerror_error_t *error     = NULL;
	static char *function        = "pysigscan_scanner_add_signature";
	static char *keyword_list[]  = { "identifier", "pattern_offset", "pattern", "signature_flags", NULL };
	const char *identifier       = NULL;
	char *pattern                = NULL;
	off64_t pattern_offset       = 0;
	Py_ssize_t identifier_size   = 0;
	int result                   = 0;
	int signature_flags          = 0;

#if defined( PY_SSIZE_T_CLEAN )
	Py_ssize_t pattern_size      = 0;
#else
	int pattern_size             = 0;
#endif

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return( NULL );
	}
	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OLs#i",
	     keyword_list,
	     &string_object,
	     &pattern_offset,
	     &pattern,
	     &pattern_size,
	     &signature_flags ) == 0 )
	{
		return( NULL );
	}
	PyErr_Clear();

	result = PyObject_IsInstance(
	          string_object,
	          (PyObject *) &PyUnicode_Type );

	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if string object is of type unicode.",
		 function );

		return( NULL );
	}
	else if( result != 0 )
	{
		PyErr_Clear();

		utf8_string_object = PyUnicode_AsUTF8String(
		                      string_object );

		if( utf8_string_object == NULL )
		{
			pysigscan_error_fetch_and_raise(
			 PyExc_RuntimeError,
			 "%s: unable to convert unicode string to UTF-8.",
			 function );

			return( NULL );
		}
#if PY_MAJOR_VERSION >= 3
		identifier = PyBytes_AsString(
		              utf8_string_object );

		identifier_size = PyBytes_Size(
		                   utf8_string_object );
#else
		identifier = PyString_AsString(
		              utf8_string_object );

		identifier_size = PyString_Size(
		                   utf8_string_object );
#endif
		Py_BEGIN_ALLOW_THREADS

		result = libsigscan_scanner_add_signature(
		          pysigscan_scanner->scanner,
	                  identifier,
	                  identifier_size,
	                  pattern_offset,
	                  (uint8_t *) pattern,
	                  pattern_size,
	                  (uint32_t) signature_flags,
		          &error );

		Py_END_ALLOW_THREADS

		Py_DecRef(
		 utf8_string_object );

		if( result != 1 )
		{
			pysigscan_error_raise(
			 error,
			 PyExc_IOError,
			 "%s: unable to add signature.",
			 function );

			libcerror_error_free(
			 &error );

			return( NULL );
		}
		Py_IncRef(
		 Py_None );

		return( Py_None );
	}
	PyErr_Clear();

#if PY_MAJOR_VERSION >= 3
	result = PyObject_IsInstance(
		  string_object,
		  (PyObject *) &PyBytes_Type );
#else
	result = PyObject_IsInstance(
		  string_object,
		  (PyObject *) &PyString_Type );
#endif
	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if string object is of type string.",
		 function );

		return( NULL );
	}
	else if( result != 0 )
	{
		PyErr_Clear();

#if PY_MAJOR_VERSION >= 3
		identifier = PyBytes_AsString(
		              string_object );

		identifier_size = PyBytes_Size(
		                   string_object );
#else
		identifier = PyString_AsString(
		              string_object );

		identifier_size = PyString_Size(
		                   string_object );
#endif
		Py_BEGIN_ALLOW_THREADS

		result = libsigscan_scanner_add_signature(
		          pysigscan_scanner->scanner,
	                  identifier,
	                  identifier_size,
	                  pattern_offset,
	                  (uint8_t *) pattern,
	                  pattern_size,
	                  (uint32_t) signature_flags,
		          &error );

		Py_END_ALLOW_THREADS

		if( result != 1 )
		{
			pysigscan_error_raise(
			 error,
			 PyExc_IOError,
			 "%s: unable to add signature.",
			 function );

			libcerror_error_free(
			 &error );

			return( NULL );
		}
		Py_IncRef(
		 Py_None );

		return( Py_None );
	}
	PyErr_Format(
	 PyExc_TypeError,
	 "%s: unsupported string object type.",
	 function );

	return( NULL );
}

/* Starts the scan
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_scan_start(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords )
{
	pysigscan_scan_state_t *pysigscan_scan_state = NULL;
	PyObject *scan_state_object                  = NULL;
	libcerror_error_t *error                     = NULL;
	static char *function                        = "pysigscan_scanner_scan_start";
	static char *keyword_list[]                  = { "scan_state", NULL };
	int result                                   = 0;

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return( NULL );
	}
	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "O",
	     keyword_list,
	     &scan_state_object ) == 0 )
	{
		return( NULL );
	}
	PyErr_Clear();

	result = PyObject_IsInstance(
	          scan_state_object,
	          (PyObject *) &pysigscan_scan_state_type_object );

	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if state object is of type pysigscan_scan_state.",
		 function );

		return( NULL );
	}
	else if( result == 0 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported state object type.",
		 function );

		return( NULL );
	}
	pysigscan_scan_state = (pysigscan_scan_state_t *) scan_state_object;

	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scanner_scan_start(
	          pysigscan_scanner->scanner,
	          pysigscan_scan_state->scan_state,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to start scan.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

/* Stops the scan
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_scan_stop(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords )
{
	pysigscan_scan_state_t *pysigscan_scan_state = NULL;
	PyObject *scan_state_object                  = NULL;
	libcerror_error_t *error                     = NULL;
	static char *function                        = "pysigscan_scanner_scan_stop";
	static char *keyword_list[]                  = { "scan_state", NULL };
	int result                                   = 0;

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return( NULL );
	}
	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "O",
	     keyword_list,
	     &scan_state_object ) == 0 )
	{
		return( NULL );
	}
	PyErr_Clear();

	result = PyObject_IsInstance(
	          scan_state_object,
	          (PyObject *) &pysigscan_scan_state_type_object );

	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if state object is of type pysigscan_scan_state.",
		 function );

		return( NULL );
	}
	else if( result == 0 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported state object type.",
		 function );

		return( NULL );
	}
	pysigscan_scan_state = (pysigscan_scan_state_t *) scan_state_object;

	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scanner_scan_stop(
		  pysigscan_scanner->scanner,
		  pysigscan_scan_state->scan_state,
		  &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to stop scan.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

/* Scans a buffer
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_scan_buffer(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords )
{
	pysigscan_scan_state_t *pysigscan_scan_state = NULL;
	PyObject *string_object                      = NULL;
	PyObject *scan_state_object                  = NULL;
	libcerror_error_t *error                     = NULL;
	static char *function                        = "pysigscan_scanner_scan_buffer";
	static char *keyword_list[]                  = { "scan_state", "buffer", NULL };
	char *buffer                                 = NULL;
	Py_ssize_t buffer_size                       = 0;
	int result                                   = 0;

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return( NULL );
	}
	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OO",
	     keyword_list,
	     &scan_state_object,
	     &string_object ) == 0 )
	{
		return( NULL );
	}
	PyErr_Clear();

	result = PyObject_IsInstance(
	          scan_state_object,
	          (PyObject *) &pysigscan_scan_state_type_object );

	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if state object is of type pysigscan_scan_state.",
		 function );

		return( NULL );
	}
	else if( result == 0 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported state object type.",
		 function );

		return( NULL );
	}
	pysigscan_scan_state = (pysigscan_scan_state_t *) scan_state_object;

#if PY_MAJOR_VERSION >= 3
	buffer = PyBytes_AsString(
		  string_object );

	buffer_size = PyBytes_Size(
		       string_object );
#else
	buffer = PyString_AsString(
		  string_object );

	buffer_size = PyString_Size(
		       string_object );
#endif
	if( ( buffer_size < 0 )
	 || ( buffer_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument buffer size value out of bounds.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scanner_scan_buffer(
		  pysigscan_scanner->scanner,
		  pysigscan_scan_state->scan_state,
		  (uint8_t *) buffer,
		  buffer_size,
		  &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to scan buffer.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

/* Scans a file
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_scan_file(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords )
{
	pysigscan_scan_state_t *pysigscan_scan_state = NULL;
	PyObject *string_object                      = NULL;
	PyObject *scan_state_object                  = NULL;
	libcerror_error_t *error                     = NULL;
	static char *function                        = "pysigscan_scanner_scan_file";
	static char *keyword_list[]                  = { "scan_state", "filename", NULL };
	const char *filename_narrow                  = NULL;
	int result                                   = 0;

#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	const wchar_t *filename_wide                 = NULL;
#else
	PyObject *utf8_string_object                 = NULL;
#endif

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return( NULL );
	}
	/* Note that PyArg_ParseTupleAndKeywords with "s" will force Unicode strings to be converted to narrow character string.
	 * On Windows the narrow character strings contains an extended ASCII string with a codepage. Hence we get a conversion
	 * exception. This will also fail if the default encoding is not set correctly. We cannot use "u" here either since that
	 * does not allow us to pass non Unicode string objects and Python (at least 2.7) does not seems to automatically upcast them.
	 */
	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OO",
	     keyword_list,
	     &scan_state_object,
	     &string_object ) == 0 )
	{
		return( NULL );
	}
	PyErr_Clear();

	result = PyObject_IsInstance(
	          scan_state_object,
	          (PyObject *) &pysigscan_scan_state_type_object );

	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if state object is of type pysigscan_scan_state.",
		 function );

		return( NULL );
	}
	else if( result == 0 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported state object type.",
		 function );

		return( NULL );
	}
	pysigscan_scan_state = (pysigscan_scan_state_t *) scan_state_object;

	PyErr_Clear();

	result = PyObject_IsInstance(
	          string_object,
	          (PyObject *) &PyUnicode_Type );

	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if string object is of type unicode.",
		 function );

		return( NULL );
	}
	else if( result != 0 )
	{
		PyErr_Clear();

#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
		filename_wide = (wchar_t *) PyUnicode_AsUnicode(
		                             string_object );

		Py_BEGIN_ALLOW_THREADS

		result = libsigscan_scanner_scan_file_wide(
		          pysigscan_scanner->scanner,
		          pysigscan_scan_state->scan_state,
	                  filename_wide,
		          &error );

		Py_END_ALLOW_THREADS
#else
		utf8_string_object = PyUnicode_AsUTF8String(
		                      string_object );

		if( utf8_string_object == NULL )
		{
			pysigscan_error_fetch_and_raise(
			 PyExc_RuntimeError,
			 "%s: unable to convert unicode string to UTF-8.",
			 function );

			return( NULL );
		}
#if PY_MAJOR_VERSION >= 3
		filename_narrow = PyBytes_AsString(
				   utf8_string_object );
#else
		filename_narrow = PyString_AsString(
				   utf8_string_object );
#endif
		Py_BEGIN_ALLOW_THREADS

		result = libsigscan_scanner_scan_file(
		          pysigscan_scanner->scanner,
		          pysigscan_scan_state->scan_state,
	                  filename_narrow,
		          &error );

		Py_END_ALLOW_THREADS

		Py_DecRef(
		 utf8_string_object );
#endif
		if( result != 1 )
		{
			pysigscan_error_raise(
			 error,
			 PyExc_IOError,
			 "%s: unable to scan file.",
			 function );

			libcerror_error_free(
			 &error );

			return( NULL );
		}
		Py_IncRef(
		 Py_None );

		return( Py_None );
	}
	PyErr_Clear();

#if PY_MAJOR_VERSION >= 3
	result = PyObject_IsInstance(
		  string_object,
		  (PyObject *) &PyBytes_Type );
#else
	result = PyObject_IsInstance(
		  string_object,
		  (PyObject *) &PyString_Type );
#endif
	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if string object is of type string.",
		 function );

		return( NULL );
	}
	else if( result != 0 )
	{
		PyErr_Clear();

#if PY_MAJOR_VERSION >= 3
		filename_narrow = PyBytes_AsString(
				   string_object );
#else
		filename_narrow = PyString_AsString(
				   string_object );
#endif
		Py_BEGIN_ALLOW_THREADS

		result = libsigscan_scanner_scan_file(
		          pysigscan_scanner->scanner,
		          pysigscan_scan_state->scan_state,
	                  filename_narrow,
		          &error );

		Py_END_ALLOW_THREADS

		if( result != 1 )
		{
			pysigscan_error_raise(
			 error,
			 PyExc_IOError,
			 "%s: unable to scan file.",
			 function );

			libcerror_error_free(
			 &error );

			return( NULL );
		}
		Py_IncRef(
		 Py_None );

		return( Py_None );
	}
	PyErr_Format(
	 PyExc_TypeError,
	 "%s: unsupported string object type.",
	 function );

	return( NULL );
}

/* Scans a file using a file-like object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scanner_scan_file_object(
           pysigscan_scanner_t *pysigscan_scanner,
           PyObject *arguments,
           PyObject *keywords )
{
	libbfio_handle_t *file_io_handle             = NULL;
	pysigscan_scan_state_t *pysigscan_scan_state = NULL;
	PyObject *file_object                        = NULL;
	PyObject *scan_state_object                  = NULL;
	libcerror_error_t *error                     = NULL;
	static char *keyword_list[]                  = { "scan_state", "file_object", NULL };
	static char *function                        = "pysigscan_scanner_scan_file_object";
	int result                                   = 0;

	if( pysigscan_scanner == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scanner.",
		 function );

		return( NULL );
	}
	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OO",
	     keyword_list,
	     &scan_state_object,
	     &file_object ) == 0 )
	{
		return( NULL );
	}
	PyErr_Clear();

	result = PyObject_IsInstance(
	          scan_state_object,
	          (PyObject *) &pysigscan_scan_state_type_object );

	if( result == -1 )
	{
		pysigscan_error_fetch_and_raise(
	         PyExc_RuntimeError,
		 "%s: unable to determine if state object is of type pysigscan_scan_state.",
		 function );

		return( NULL );
	}
	else if( result == 0 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported state object type.",
		 function );

		return( NULL );
	}
	pysigscan_scan_state = (pysigscan_scan_state_t *) scan_state_object;

	if( pysigscan_file_object_initialize(
	     &file_io_handle,
	     file_object,
	     &error ) != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to initialize file IO handle.",
		 function );

		libcerror_error_free(
		 &error );

		goto on_error;
	}
	Py_BEGIN_ALLOW_THREADS

	result = libsigscan_scanner_scan_file_io_handle(
	          pysigscan_scanner->scanner,
	          pysigscan_scan_state->scan_state,
	          file_io_handle,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to scan file.",
		 function );

		libcerror_error_free(
		 &error );

		goto on_error;
	}
	Py_BEGIN_ALLOW_THREADS

	result = libbfio_handle_free(
	          &file_io_handle,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pysigscan_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to free libbfio file IO handle.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );

on_error:
	if( file_io_handle != NULL )
	{
		libbfio_handle_free(
		 &file_io_handle,
		 NULL );
	}
	return( NULL );
}

