include_HEADERS = \
	libsigscan.h

pkginclude_HEADERS = \
	libsigscan/codepage.h \
	libsigscan/definitions.h \
	libsigscan/error.h \
	libsigscan/extern.h \
	libsigscan/features.h \
	libsigscan/types.h

EXTRA_DIST = \
	libsigscan.h.in \
	libsigscan/definitions.h.in \
	libsigscan/features.h.in \
	libsigscan/types.h.in

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	-rm -f libsigscan.h
	-rm -f libsigscan/definitions.h
	-rm -f libsigscan/features.h
	-rm -f libsigscan/types.h
	-rm -f Makefile

