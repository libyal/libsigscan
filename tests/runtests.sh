#!/bin/sh
# Script to run tests
#
# Version: 20201121

if test -f ${PWD}/libsigscan/.libs/libsigscan.1.dylib && test -f ./pysigscan/.libs/pysigscan.so;
then
	install_name_tool -change /usr/local/lib/libsigscan.1.dylib ${PWD}/libsigscan/.libs/libsigscan.1.dylib ./pysigscan/.libs/pysigscan.so;
fi

make check CHECK_WITH_STDERR=1;
RESULT=$?;

if test ${RESULT} -ne 0 && test -f tests/test-suite.log;
then
	cat tests/test-suite.log;
fi
exit ${RESULT};

