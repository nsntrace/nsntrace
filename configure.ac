# AC_INIT([package],
#         [version],
#         [bug reports],
#         [tar-ball name])
AC_INIT([nsntrace],
        [2],
        [https://github.com/jonasdn/nsntrace/issues],
        [nsntrace])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
                 src/Makefile
                 man/Makefile
                 tests/Makefile])

# Check for pcap
AC_CHECK_LIB([pcap],[pcap_create])
AC_CHECK_HEADERS([pcap/pcap.h],[],AC_MSG_ERROR([You need to have libpcap development package installed]))

have_manpages=no
AC_ARG_ENABLE(manpages, AS_HELP_STRING([--disable-manpages],[disable manpages]))
AC_PATH_PROG([XSLTPROC], xsltproc)
AS_IF([test "x$enable_manpages" != xno], [
       have_manpages=yes
       AS_IF([test -z "$XSLTPROC"],
             AC_MSG_ERROR([You need xsltproc for man pages]))
])
AM_CONDITIONAL(ENABLE_MANPAGES, [test "x$have_manpages" = "xyes"])

AC_CHECK_PROG(IPTABLES_CHECK,iptables,yes,no,"$PATH:/sbin:/usr/sbin")
if test x"$IPTABLES_CHECK" != x"yes"; then
   AC_MSG_ERROR([You need to have iptables installed])
fi

# Check for libnl
PKG_CHECK_MODULES([LIBNL], [libnl-route-3.0])

AC_OUTPUT
