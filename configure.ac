AC_INIT([nsntrace], [1.0], [https://github.com/jonasdn/ntrace])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

# Check for pcap
AC_CHECK_LIB([pcap],[pcap_create])
AC_CHECK_HEADERS([pcap/pcap.h])

AC_CHECK_PROG(IPTABLES_CHECK,iptables,yes)
if test x"$IPTABLES_CHECK" != x"yes"; then
   AC_MSG_ERROR([You need to have iptables installed,])
fi

# Check for libnl
PKG_CHECK_MODULES([LIBNL], [libnl-route-3.0])

AC_OUTPUT
