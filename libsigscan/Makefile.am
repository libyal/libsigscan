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
	@LIBSIGSCAN_DLL_EXPORT@

lib_LTLIBRARIES = libsigscan.la

libsigscan_la_SOURCES = \
	libsigscan.c \
	libsigscan_byte_value_group.c libsigscan_byte_value_group.h \
	libsigscan_codepage.h \
	libsigscan_definitions.h \
	libsigscan_error.c libsigscan_error.h \
	libsigscan_extern.h \
	libsigscan_libbfio.h \
	libsigscan_libcdata.h \
	libsigscan_libcerror.h \
	libsigscan_libclocale.h \
	libsigscan_libcnotify.h \
	libsigscan_libuna.h \
	libsigscan_notify.c libsigscan_notify.h \
	libsigscan_offset_group.c libsigscan_offset_group.h \
	libsigscan_offsets_list.c libsigscan_offsets_list.h \
	libsigscan_pattern_weights.c libsigscan_pattern_weights.h \
	libsigscan_scan_object.c libsigscan_scan_object.h \
	libsigscan_scan_result.c libsigscan_scan_result.h \
	libsigscan_scan_state.c libsigscan_scan_state.h \
	libsigscan_scan_tree.c libsigscan_scan_tree.h \
	libsigscan_scan_tree_node.c libsigscan_scan_tree_node.h \
	libsigscan_scanner.c libsigscan_scanner.h \
	libsigscan_signature.c libsigscan_signature.h \
	libsigscan_signature_group.c libsigscan_signature_group.h \
	libsigscan_signature_table.c libsigscan_signature_table.h \
	libsigscan_signatures_list.c libsigscan_signatures_list.h \
	libsigscan_skip_table.c libsigscan_skip_table.h \
	libsigscan_support.c libsigscan_support.h \
	libsigscan_types.h \
	libsigscan_unused.h \
	libsigscan_weight_group.c libsigscan_weight_group.h

libsigscan_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	@LIBCTHREADS_LIBADD@ \
	@LIBCDATA_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCSPLIT_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBCPATH_LIBADD@ \
	@LIBBFIO_LIBADD@ \
	@PTHREAD_LIBADD@

libsigscan_la_LDFLAGS = -no-undefined -version-info 1:0:0

EXTRA_DIST = \
	libsigscan_definitions.h.in \
	libsigscan.rc \
	libsigscan.rc.in

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f libsigscan_definitions.h
	/bin/rm -f libsigscan.rc
	/bin/rm -f Makefile

splint:
	@echo "Running splint on libsigscan ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(libsigscan_la_SOURCES)

