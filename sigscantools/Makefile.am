AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCDATA_CPPFLAGS@ \
	@LIBCLOCALE_CPPFLAGS@ \
	@LIBCNOTIFY_CPPFLAGS@ \
	@LIBCSPLIT_CPPFLAGS@ \
	@LIBUNA_CPPFLAGS@ \
	@LIBCFILE_CPPFLAGS@ \
	@LIBCPATH_CPPFLAGS@ \
	@LIBBFIO_CPPFLAGS@ \
	@LIBSIGSCAN_DLL_IMPORT@

AM_LDFLAGS = @STATIC_LDFLAGS@

bin_PROGRAMS = \
	sigscan

sigscan_SOURCES = \
	scan_handle.c scan_handle.h \
	sigscan.c \
	sigscantools_getopt.c sigscantools_getopt.h \
	sigscantools_i18n.h \
	sigscantools_libbfio.h \
	sigscantools_libcdata.h \
	sigscantools_libcerror.h \
	sigscantools_libcfile.h \
	sigscantools_libclocale.h \
	sigscantools_libcnotify.h \
	sigscantools_libsigscan.h \
	sigscantools_libuna.h \
	sigscantools_output.c sigscantools_output.h \
	sigscantools_signal.c sigscantools_signal.h \
	sigscantools_unused.h

sigscan_LDADD = \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	../libsigscan/libsigscan.la \
	@LIBCERROR_LIBADD@ \
	@LIBINTL@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

splint:
	@echo "Running splint on sigscan..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(sigscan_SOURCES)

