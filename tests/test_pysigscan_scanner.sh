#!/bin/bash
# Python-bindings scanner testing script
#
# Version: 201801801

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

TEST_RUNNER="tests/test_runner.sh";

if ! test -f "${TEST_RUNNER}";
then
	TEST_RUNNER="./test_runner.sh";
fi

if ! test -f "${TEST_RUNNER}";
then
	echo "Missing test runner: ${TEST_RUNNER}";

	exit ${EXIT_FAILURE};
fi

source ${TEST_RUNNER};

run_test_with_arguments "pysigscan" ${TEST_SCRIPT};
RESULT=$?;

exit ${RESULT};

