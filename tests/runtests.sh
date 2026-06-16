#!/bin/sh
# Script to run tests
#
# Version: 20260609

if test -f ${PWD}/libsigscan/.libs/libsigscan.1.dylib && test -f ./pysigscan/.libs/pysigscan.so
then
	install_name_tool -change /usr/local/lib/libsigscan.1.dylib ${PWD}/libsigscan/.libs/libsigscan.1.dylib ./pysigscan/.libs/pysigscan.so
fi

make check-build > /dev/null

make check $@
RESULT=$?

if test ${RESULT} -ne 0
then
	find . -name \*.log -path \*.dir/\*/\*.log -print -exec cat {} \;
fi
exit ${RESULT}

