bin_PROGRAMS = nsntrace

warnings = -Wall -Wno-missing-braces

nsntrace_SOURCES = nsntrace.c cmd.c net.c capture.c
nsntrace_CPPFLAGS = $(LIBNL_CFLAGS) $(warnings)
nsntrace_LDFLAGS = $(LIBNL_LIBS)
