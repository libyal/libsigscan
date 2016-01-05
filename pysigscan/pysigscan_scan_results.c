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

#include <common.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pysigscan_libcerror.h"
#include "pysigscan_libsigscan.h"
#include "pysigscan_python.h"
#include "pysigscan_scan_result.h"
#include "pysigscan_scan_results.h"
#include "pysigscan_scan_state.h"

PySequenceMethods pysigscan_scan_results_sequence_methods = {
	/* sq_length */
	(lenfunc) pysigscan_scan_results_len,
	/* sq_concat */
	0,
	/* sq_repeat */
	0,
	/* sq_item */
	(ssizeargfunc) pysigscan_scan_results_getitem,
	/* sq_slice */
	0,
	/* sq_ass_item */
	0,
	/* sq_ass_slice */
	0,
	/* sq_contains */
	0,
	/* sq_inplace_concat */
	0,
	/* sq_inplace_repeat */
	0
};

PyTypeObject pysigscan_scan_results_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pysigscan._scan_results",
	/* tp_basicsize */
	sizeof( pysigscan_scan_results_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pysigscan_scan_results_free,
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
	&pysigscan_scan_results_sequence_methods,
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
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
	/* tp_doc */
	"internal pysigscan scan results sequence and iterator object",
	/* tp_traverse */
	0,
	/* tp_clear */
	0,
	/* tp_richcompare */
	0,
	/* tp_weaklistoffset */
	0,
	/* tp_iter */
	(getiterfunc) pysigscan_scan_results_iter,
	/* tp_iternext */
	(iternextfunc) pysigscan_scan_results_iternext,
	/* tp_methods */
	0,
	/* tp_members */
	0,
	/* tp_getset */
	0,
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
	(initproc) pysigscan_scan_results_init,
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

/* Creates a new scan results object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pysigscan_scan_results_new(
           pysigscan_scan_state_t *scan_state_object,
           PyObject* (*get_scan_result_by_index)(
                        pysigscan_scan_state_t *scan_state_object,
                        int result_index ),
           int number_of_results )
{
	pysigscan_scan_results_t *pysigscan_scan_results = NULL;
	static char *function                            = "pysigscan_scan_results_new";

	if( scan_state_object == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan state object.",
		 function );

		return( NULL );
	}
	if( get_scan_result_by_index == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid get scan result by index function.",
		 function );

		return( NULL );
	}
	/* Make sure the scan results values are initialized
	 */
	pysigscan_scan_results = PyObject_New(
	                          struct pysigscan_scan_results,
	                          &pysigscan_scan_results_type_object );

	if( pysigscan_scan_results == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize scan results.",
		 function );

		goto on_error;
	}
	if( pysigscan_scan_results_init(
	     pysigscan_scan_results ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize scan results.",
		 function );

		goto on_error;
	}
	pysigscan_scan_results->scan_state_object        = scan_state_object;
	pysigscan_scan_results->get_scan_result_by_index = get_scan_result_by_index;
	pysigscan_scan_results->number_of_results        = number_of_results;

	Py_IncRef(
	 (PyObject *) pysigscan_scan_results->scan_state_object );

	return( (PyObject *) pysigscan_scan_results );

on_error:
	if( pysigscan_scan_results != NULL )
	{
		Py_DecRef(
		 (PyObject *) pysigscan_scan_results );
	}
	return( NULL );
}

/* Intializes a scan results object
 * Returns 0 if successful or -1 on error
 */
int pysigscan_scan_results_init(
     pysigscan_scan_results_t *pysigscan_scan_results )
{
	static char *function = "pysigscan_scan_results_init";

	if( pysigscan_scan_results == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results.",
		 function );

		return( -1 );
	}
	/* Make sure the scan results values are initialized
	 */
	pysigscan_scan_results->scan_state_object        = NULL;
	pysigscan_scan_results->get_scan_result_by_index = NULL;
	pysigscan_scan_results->result_index             = 0;
	pysigscan_scan_results->number_of_results        = 0;

	return( 0 );
}

/* Frees a scan results object
 */
void pysigscan_scan_results_free(
      pysigscan_scan_results_t *pysigscan_scan_results )
{
	struct _typeobject *ob_type = NULL;
	static char *function       = "pysigscan_scan_results_free";

	if( pysigscan_scan_results == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results.",
		 function );

		return;
	}
	ob_type = Py_TYPE(
	           pysigscan_scan_results );

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
	if( pysigscan_scan_results->scan_state_object != NULL )
	{
		Py_DecRef(
		 (PyObject *) pysigscan_scan_results->scan_state_object );
	}
	ob_type->tp_free(
	 (PyObject*) pysigscan_scan_results );
}

/* The scan results len() function
 */
Py_ssize_t pysigscan_scan_results_len(
            pysigscan_scan_results_t *pysigscan_scan_results )
{
	static char *function = "pysigscan_scan_results_len";

	if( pysigscan_scan_results == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results.",
		 function );

		return( -1 );
	}
	return( (Py_ssize_t) pysigscan_scan_results->number_of_results );
}

/* The scan results getitem() function
 */
PyObject *pysigscan_scan_results_getitem(
           pysigscan_scan_results_t *pysigscan_scan_results,
           Py_ssize_t item_index )
{
	PyObject *scan_result_object = NULL;
	static char *function        = "pysigscan_scan_results_getitem";

	if( pysigscan_scan_results == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results.",
		 function );

		return( NULL );
	}
	if( pysigscan_scan_results->get_scan_result_by_index == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results - missing get scan result by index function.",
		 function );

		return( NULL );
	}
	if( pysigscan_scan_results->number_of_results < 0 )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results - invalid number of results.",
		 function );

		return( NULL );
	}
	if( ( item_index < 0 )
	 || ( item_index >= (Py_ssize_t) pysigscan_scan_results->number_of_results ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid invalid item index value out of bounds.",
		 function );

		return( NULL );
	}
	scan_result_object = pysigscan_scan_results->get_scan_result_by_index(
	                      pysigscan_scan_results->scan_state_object,
	                      (int) item_index );

	return( scan_result_object );
}

/* The scan results iter() function
 */
PyObject *pysigscan_scan_results_iter(
           pysigscan_scan_results_t *pysigscan_scan_results )
{
	static char *function = "pysigscan_scan_results_iter";

	if( pysigscan_scan_results == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results.",
		 function );

		return( NULL );
	}
	Py_IncRef(
	 (PyObject *) pysigscan_scan_results );

	return( (PyObject *) pysigscan_scan_results );
}

/* The scan results iternext() function
 */
PyObject *pysigscan_scan_results_iternext(
           pysigscan_scan_results_t *pysigscan_scan_results )
{
	PyObject *scan_result_object = NULL;
	static char *function        = "pysigscan_scan_results_iternext";

	if( pysigscan_scan_results == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results.",
		 function );

		return( NULL );
	}
	if( pysigscan_scan_results->get_scan_result_by_index == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results - missing get scan result by index function.",
		 function );

		return( NULL );
	}
	if( pysigscan_scan_results->result_index < 0 )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results - invalid result index.",
		 function );

		return( NULL );
	}
	if( pysigscan_scan_results->number_of_results < 0 )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid scan results - invalid number of results.",
		 function );

		return( NULL );
	}
	if( pysigscan_scan_results->result_index >= pysigscan_scan_results->number_of_results )
	{
		PyErr_SetNone(
		 PyExc_StopIteration );

		return( NULL );
	}
	scan_result_object = pysigscan_scan_results->get_scan_result_by_index(
	                      pysigscan_scan_results->scan_state_object,
	                      pysigscan_scan_results->result_index );

	if( scan_result_object != NULL )
	{
		pysigscan_scan_results->result_index++;
	}
	return( scan_result_object );
}

