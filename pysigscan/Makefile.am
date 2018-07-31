if HAVE_PYTHON
AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCDATA_CPPFLAGS@ \
	@LIBCLOCALE_CPPFLAGS@ \
	@LIBCSPLIT_CPPFLAGS@ \
	@LIBUNA_CPPFLAGS@ \
	@LIBCFILE_CPPFLAGS@ \
	@LIBCPATH_CPPFLAGS@ \
	@LIBBFIO_CPPFLAGS@ \
	@LIBSIGSCAN_DLL_IMPORT@

pyexec_LTLIBRARIES = pysigscan.la

pysigscan_la_SOURCES = \
	pysigscan.c pysigscan.h \
	pysigscan_error.c pysigscan_error.h \
	pysigscan_file_object_io_handle.c pysigscan_file_object_io_handle.h \
	pysigscan_integer.c pysigscan_integer.h \
	pysigscan_libbfio.h \
	pysigscan_libcerror.h \
	pysigscan_libclocale.h \
	pysigscan_libsigscan.h \
	pysigscan_python.h \
	pysigscan_scan_result.c pysigscan_scan_result.h \
	pysigscan_scan_results.c pysigscan_scan_results.h \
	pysigscan_scan_state.c pysigscan_scan_state.h \
	pysigscan_scanner.c pysigscan_scanner.h \
	pysigscan_signature_flags.c pysigscan_signature_flags.h \
	pysigscan_unused.h

pysigscan_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	../libsigscan/libsigscan.la \
	@LIBCDATA_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCSPLIT_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBCPATH_LIBADD@ \
	@LIBBFIO_LIBADD@

pysigscan_la_CPPFLAGS = $(PYTHON_CPPFLAGS)
pysigscan_la_LDFLAGS  = -module -avoid-version $(PYTHON_LDFLAGS)

endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

