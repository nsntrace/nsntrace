#!/bin/sh

RET=0

check_return_code () {
	EXPECTED="${1}"
	shift 1

	echo "Calling nsntrace ${*} ..."

	sudo ../src/nsntrace "${@}"

	RESULT="${?}"

	if [ "${EXPECTED}" != "${RESULT}" ] ; then
		echo "Did not return with ${EXPECTED} (saw: ${RESULT})"
		RET="1"
	fi
}

check_return_code 0 /bin/true
check_return_code 1 /bin/false
check_return_code 1 /bin/does-not-exist

check_return_code 1 -u username-does-not-exist /bin/true
check_return_code 1 -f "broken filter" /bin/true
check_return_code 1 -o /path/does/not/exist /bin/true
check_return_code 1 -d invalid_device /bin/true

rm -rf *.pcap

exit ${RET}
