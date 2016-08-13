bin_PROGRAMS = nsntrace

warnings = -Wall -Wno-missing-braces

headers =			\
	net.h			\
	cmd.h			\
	capture.h

sources =			\
	nsntrace.c		\
	cmd.c			\
	net.c			\
	capture.c

nsntrace_SOURCES = $(headers) $(sources)
nsntrace_CPPFLAGS = $(LIBNL_CFLAGS) $(warnings)
nsntrace_LDFLAGS = -pthread
nsntrace_LDADD = $(LIBNL_LIBS)
