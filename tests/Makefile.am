AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCSTRING_CPPFLAGS@ \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCTHREADS_CPPFLAGS@ \
	@LIBCDATA_CPPFLAGS@ \
	@LIBCLOCALE_CPPFLAGS@ \
	@LIBCNOTIFY_CPPFLAGS@ \
	@LIBCSPLIT_CPPFLAGS@ \
	@LIBUNA_CPPFLAGS@ \
	@LIBCFILE_CPPFLAGS@ \
	@LIBCPATH_CPPFLAGS@ \
	@LIBBFIO_CPPFLAGS@ \
	@LIBSIGSCAN_DLL_IMPORT@

if HAVE_PYTHON
TESTS_PYSIGSCAN = \
	test_pysigscan_scanner.sh
endif

TESTS = \
	test_scanner.sh \
	test_sigscan.sh \
	$(TESTS_PYSIGSCAN)

check_SCRIPTS = \
	pysigscan_test_scanner.py \
	test_pysigscan_scanner.sh \
	test_scanner.sh \
	test_sigscan.sh \
	test_runner.sh

EXTRA_DIST = \
	$(check_SCRIPTS)

check_PROGRAMS = \
	sigscan_test_scanner

sigscan_test_scanner_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libcstring.h \
	sigscan_test_libsigscan.h \
	sigscan_test_scanner.c \
	sigscan_test_unused.h

sigscan_test_scanner_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

