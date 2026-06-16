AM_CPPFLAGS = \
	-I../include -I$(top_srcdir)/include \
	-I../common -I$(top_srcdir)/common \
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

check_PYTHONdir = $(abs_top_builddir)

BUILT_SOURCES = package.m4

check_AUTOTESTS = \
	test_library \
	test_manpages \
	test_tools

if HAVE_PYTHON_TESTS
check_AUTOTESTS += test_python_module
endif

check_PYTHON_SCRIPTS = \
	pysigscan_test_scanner.py \
	pysigscan_test_support.py

check_PROGRAMS = \
	sigscan_test_byte_value_group \
	sigscan_test_error \
	sigscan_test_identifier \
	sigscan_test_notify \
	sigscan_test_offset_group \
	sigscan_test_offsets_list \
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
	sigscan_test_signatures_list \
	sigscan_test_skip_table \
	sigscan_test_support \
	sigscan_test_weight_group

sigscan_test_byte_value_group_SOURCES = \
	sigscan_test_byte_value_group.c \
	sigscan_test_libcdata.h \
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

sigscan_test_identifier_SOURCES = \
	sigscan_test_identifier.c \
	sigscan_test_libcdata.h \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_unused.h

sigscan_test_identifier_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

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

sigscan_test_offsets_list_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_offsets_list.c \
	sigscan_test_unused.h

sigscan_test_offsets_list_LDADD = \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_pattern_weights_SOURCES = \
	sigscan_test_libcdata.h \
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
	sigscan_test_libcdata.h \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scan_state.c \
	sigscan_test_unused.h

sigscan_test_scan_state_LDADD = \
	@LIBCDATA_LIBADD@ \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_scan_tree_SOURCES = \
	sigscan_test_libcdata.h \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scan_tree.c \
	sigscan_test_unused.h

sigscan_test_scan_tree_LDADD = \
	@LIBCDATA_LIBADD@ \
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
	sigscan_test_functions.c sigscan_test_functions.h \
	sigscan_test_getopt.c sigscan_test_getopt.h \
	sigscan_test_libbfio.h \
	sigscan_test_libcerror.h \
	sigscan_test_libclocale.h \
	sigscan_test_libcnotify.h \
	sigscan_test_libsigscan.h \
	sigscan_test_libuna.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_scanner.c

sigscan_test_scanner_LDADD = \
	@LIBBFIO_LIBADD@ \
	@LIBCPATH_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCSPLIT_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCDATA_LIBADD@ \
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
	sigscan_test_libcdata.h \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_signature_table.c \
	sigscan_test_unused.h

sigscan_test_signature_table_LDADD = \
	@LIBCDATA_LIBADD@ \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@

sigscan_test_signatures_list_SOURCES = \
	sigscan_test_libcerror.h \
	sigscan_test_libsigscan.h \
	sigscan_test_macros.h \
	sigscan_test_memory.c sigscan_test_memory.h \
	sigscan_test_signatures_list.c \
	sigscan_test_unused.h

sigscan_test_signatures_list_LDADD = \
	@LIBCDATA_LIBADD@ \
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
	@LIBCDATA_LIBADD@ \
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

AUTOM4TE = autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest

SUFFIXES = .at

.at:
	$(AM_V_GEN)rm -f $@ $@.tmp; \
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $< && \
	mv $@.tmp $@

atconfig: $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status tests/$@

check-build: $(check_PROGRAMS)

check-local: $(check_AUTOTESTS)
	@fail=0; \
	for test_suite in $(check_AUTOTESTS); do \
		$(AM_TESTS_ENVIRONMENT) $(SHELL) "./$$test_suite" $(TESTSUITEFLAGS) || fail=1; \
		echo ""; \
	done; \
	exit $$fail

clean-local:
	for test_suite in $(check_AUTOTESTS); do \
		test ! -f "$$test_suite" || $(SHELL) "./$$test_suite" --clean; \
	done

package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN):; \
	{ \
	  echo 'm4_define([AT_PACKAGE_NAME], [$(PACKAGE_NAME)])' ; \
	  echo 'm4_define([AT_PACKAGE_TARNAME], [$(PACKAGE_TARNAME)])' ; \
	  echo 'm4_define([AT_PACKAGE_VERSION], [$(PACKAGE_VERSION)])' ; \
	  echo 'm4_define([AT_PACKAGE_STRING], [$(PACKAGE_STRING)])' ; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])' ; \
	} > $@

test_inputs_libsigscan.at: generate_test_inputs.sh
	$(SHELL) $(srcdir)/generate_test_inputs.sh $(PACKAGE_NAME) libsigscan

test_inputs_sigscan.at: generate_test_inputs.sh
	$(SHELL) $(srcdir)/generate_test_inputs.sh $(PACKAGE_NAME) sigscan

test_library: \
	package.m4 \
	test_inputs_libsigscan.at \
	test_library.at \
	test_macros.at

test_manpages: \
	package.m4 \
	test_manpages.at

test_python_module: \
	package.m4 \
	test_python_module.at

test_tools: \
	package.m4 \
	test_inputs_sigscan.at \
	test_macros.at \
	test_tools.at

EXTRA_DIST = \
	$(check_AUTOTESTS:=.at) \
	$(check_PYTHON_SCRIPTS) \
	generate_test_inputs.sh \
	package.m4 \
	test_macros.at

CLEANFILES = \
	$(check_AUTOTESTS) \
	*.exe \
	*.tmp \
	notify_stream.log \
	test_inputs_*.at

DISTCLEANFILES = \
	*.log \
	atconfig \
	Makefile \
	Makefile.in

