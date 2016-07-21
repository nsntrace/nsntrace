if ENABLE_MANPAGES
man1_MANS = nsntrace.1

XSLTPROC_FLAGS = --nonet

nsntrace.1: nsntrace.xml
	$(XSLTPROC) $(XSLTPROC_FLAGS) -o $@ $(srcdir)/man.xsl $<

EXTRA_DIST = nsntrace.xml man.xsl
CLEANFILES = $(man1_MANS)
endif
