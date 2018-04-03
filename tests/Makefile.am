AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
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
	@PTHREAD_CPPFLAGS@ \
	@LIBSIGSCAN_DLL_IMPORT@

if HAVE_PYTHON_TESTS
TESTS_PYSIGSCAN = \
	test_python_module.sh \
	test_pysigscan_scanner.sh
endif

TESTS = \
	test_library.sh \
	test_sigscan.sh \
	$(TESTS_PYSIGSCAN)

check_SCRIPTS = \
	pysigscan_test_scanner.py \
	pysigscan_test_support.py \
	test_library.sh \
	test_pysigscan_scanner.sh \
	test_python_module.sh \
	test_sigscan.sh \
	test_runner.sh

EXTRA_DIST = \
	$(check_SCRIPTS)

check_PROGRAMS = \
	sigscan_test_byte_value_group \
	sigscan_test_error \
	sigscan_test_notify \
	sigscan_test_offset_group \
	sigscan_test_pattern_weights \
	sigscan_test_scan_object \
	sigscan_test_scan_result \
	sigscan_test_scan_state \
	sigscan_test_scan_tree \
	sigscan_test_scan_tree_node \
	sigscan_test_scanner \
	sigscan_test_signature \
	sigscan_test_signature_group \
	sigscan_test_signature_table \
	sigscan_test_skip_table \
	sigscan_test_support \
	sigscan_test_weight_group

sigscan_test_byte_value_group_SOURCES = \
	sigscan_test_byte_value_group.c \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_unused.h

sigscan_test_byte_value_group_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_error_SOURCES = \
	sigscan_test_error.c \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_unused.h

sigscan_test_error_LDADD = \
	../libsigscan/libsigscan.la

sigscan_test_notify_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_notify.c \
	sigscan_test_unused.h

sigscan_test_notify_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_offset_group_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_offset_group.c \
	sigscan_test_unused.h

sigscan_test_offset_group_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_pattern_weights_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_pattern_weights.c \
	sigscan_test_unused.h

sigscan_test_pattern_weights_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_scan_object_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scan_object.c \
	sigscan_test_unused.h

sigscan_test_scan_object_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_scan_result_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scan_result.c \
	sigscan_test_unused.h

sigscan_test_scan_result_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_scan_state_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scan_state.c \
	sigscan_test_unused.h

sigscan_test_scan_state_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_scan_tree_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scan_tree.c \
	sigscan_test_unused.h

sigscan_test_scan_tree_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_scan_tree_node_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scan_tree_node.c \
	sigscan_test_unused.h

sigscan_test_scan_tree_node_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_scanner_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scanner.c \
	sigscan_test_unused.h

sigscan_test_scanner_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_signature_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_signature.c \
	sigscan_test_unused.h

sigscan_test_signature_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_signature_group_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_signature_group.c \
	sigscan_test_unused.h

sigscan_test_signature_group_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_signature_table_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_signature_table.c \
	sigscan_test_unused.h

sigscan_test_signature_table_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_skip_table_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_skip_table.c \
	sigscan_test_unused.h

sigscan_test_skip_table_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_support_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_support.c \
	sigscan_test_unused.h

sigscan_test_support_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_weight_group_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_unused.h \
	sigscan_test_weight_group.c

sigscan_test_weight_group_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

