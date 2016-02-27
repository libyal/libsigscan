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
	/bin/rm -f libsigscan.h
	/bin/rm -f libsigscan/definitions.h
	/bin/rm -f libsigscan/features.h
	/bin/rm -f libsigscan/types.h
	/bin/rm -f Makefile

