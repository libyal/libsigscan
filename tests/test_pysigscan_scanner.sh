#!/bin/bash
# Python-bindings scanner testing script
#
# Version: 20170829

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

TEST_SCRIPT="pysigscan_test_scanner.py";

if ! test -z ${SKIP_PYTHON_TESTS};
then
	exit ${EXIT_IGNORE};
fi

PYTHON=`which python${PYTHON_VERSION} 2> /dev/null`;

if ! test -x ${PYTHON};
then
	echo "Missing executable: ${PYTHON}";

	exit ${EXIT_FAILURE};
fi

if ! test -f ${TEST_SCRIPT};
then
	echo "Missing script: ${TEST_SCRIPT}";

	exit ${EXIT_FAILURE};
fi

if test `uname -s` = 'Darwin';
then
	DYLD_LIBRARY_PATH="../libpysigscan/.libs/" PYTHONPATH="../pypysigscan/.libs/" ${PYTHON} ${TEST_SCRIPT};
	RESULT=$?;
else
	LD_LIBRARY_PATH="../libpysigscan/.libs/" PYTHONPATH="../pypysigscan/.libs/" ${PYTHON} ${TEST_SCRIPT};
	RESULT=$?;
fi

if test ${RESULT} -ne ${EXIT_SUCCESS};
then
	exit ${EXIT_FAILURE};
fi

exit ${EXIT_SUCCESS};

