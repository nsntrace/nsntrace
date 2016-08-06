TESTS =			\
	check_namespaced.sh	\
	check_cleanup.sh	\
	check_return_code.sh

check_namespaced.sh: udp_send

udp_send: udp_send.c
	$(CC) $^ -o $@

CLEANFILES = udp_send
EXTRA_DIST = $(TESTS) test_program_dummy.sh udp_send.c
