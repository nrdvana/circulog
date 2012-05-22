ifeq ($(QUIET),yes)
COMPILE_C   = @echo '  Compile   $<';
COMPILE_CXX = @echo '  Compile   $<';
LINK        = @echo '  * Link    $@';
MKSTATICLIB = @echo '  * Mklib   $@';
MKSHAREDLIB = @echo '  * MkShLib $@';
INST        = @inst() { echo "  > Install $$@"; $(INSTALL) "$$@"; }; inst
else
INST        = $(INSTALL)
endif

COMPILE_C   += $(CC) -MMD $(CFLAGS) -c
COMPILE_CXX += $(CXX) -MMD $(CXXFLAGS) -c
LINK        += $(CXX) $(LDFLAGS)
MKSTATICLIB += $(AR) rcs
MKSHAREDLIB += $(CC) -shared -Wl,-soname,`echo '$@'|sed 's/\.[^.]*\.[^.]*$$//'` -o

STRIP = strip
INSTALL = install

CFLAGS += -Wall -std=gnu99 $(INCPATH) $(CCOPTS)
CXXFLAGS += -Wall -std=gnu++0x $(INCPATH) $(CCOPTS)
#LDFLAGS +=

-include *.d

Makefile: $(buildroot)/config.mk $(srcdir)/Makefile.mlc
	@echo 'Updating    $@'; cat $(buildroot)/config.mk $(srcdir)/Makefile.mlc >$@

%.cpp: $(srcdir)/%.cpp
	@ln -s $< $@

%.c: $(srcdir)/%.c
	@ln -s $< $@

%.o: %.c
	$(COMPILE_C) -o $@ $<

%.o: %.cpp
	$(COMPILE_CXX) -o $@ $<

install: destdir_is_set

destdir_is_set:
	@[ -n "$(DESTDIR)" -a "`realpath '$(DESTDIR)'`" != "/" ] || { echo; echo "SET DESTDIR BEFORE INSTALLING!"; echo; false; }

.PHONY: install destdir_is_set