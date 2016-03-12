#!/bin/bash
# Library scanner type testing script
#
# Version: 20160128

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

TEST_PREFIX=`pwd`;
TEST_PREFIX=`dirname ${TEST_PREFIX}`;
TEST_PREFIX=`basename ${TEST_PREFIX} | sed 's/^lib//'`;

if ! test -z ${SKIP_LIBRARY_TESTS};
then
	exit ${EXIT_IGNORE};
fi

TEST_SCANNER="./${TEST_PREFIX}_test_scanner";

if ! test -x ${TEST_SCANNER};
then
	TEST_SCANNER="${TEST_PREFIX}_test_scanner.exe";
fi

if ! test -x ${TEST_SCANNER};
then
	echo "Missing executable: ${TEST_SCANNER}";

	exit ${EXIT_FAILURE};
fi

TEST_RUNNER="tests/test_runner.sh";

if ! test -x ${TEST_RUNNER};
then
	TEST_RUNNER="./test_runner.sh";
fi

if ! test -x ${TEST_RUNNER};
then
	echo "Missing test runner: ${TEST_RUNNER}";

	exit ${EXIT_FAILURE};
fi

echo -n -e "Testing scanner\t"

TMPDIR="tmp$$";

rm -rf ${TMPDIR};
mkdir ${TMPDIR};

${TEST_RUNNER} ${TMPDIR} ${TEST_SCANNER};

RESULT=$?;

rm -rf ${TMPDIR};

if test ${RESULT} -ne 0;
then
	echo "(FAIL)";
else
	echo "(PASS)";
fi
echo "";

if test ${RESULT} -ne 0;
then
	exit ${EXIT_FAILURE};
fi

exit ${EXIT_SUCCESS};

