if HAVE_LIB_FUZZING_ENGINE
AM_CPPFLAGS = \
	-I../include -I$(top_srcdir)/include \
	-I../common -I$(top_srcdir)/common

bin_PROGRAMS = \
	scanner_fuzzer

scanner_fuzzer_SOURCES = \
	ossfuzz_libsigscan.h \
	scanner_fuzzer.cc

scanner_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libsigscan/libsigscan.la
endif

DISTCLEANFILES = \
	Makefile \
	Makefile.in

splint-local:
	@echo "Running splint on scanner_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(scanner_fuzzer_SOURCES)

