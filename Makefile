#!/usr/bin/make

ifeq ($(VERBOSE),true)
  V=
else
  V=@
endif

PWD?=$(shell pwd)
BUILDROOT?=$(CURDIR)/../..

TARGET_ARCH?=$(shell uname -m)

CFLAGS?=-Wall -O2 -fpic

MAKEDEPEND?=$(CC) -M -MT$(OBJDIR)/$*.o $(CFLAGS) $(DEFS) $(VERSION_DEFS) $(INCS) -o $(DEPDIR)/$*.d $<

VPATH=src

INCLUDE_PATHS+=inc
#INCLUDE_PATHS+=$(OPENSSL_INC_DIR)

SOURCES=miniweb.c
SOURCES+=miniweb_main.c

LIBRARIES=ssl crypto
DEFS+=-DENABLE_DEBUG_PRINTS=1
DEFS+=-DMINIWEB_SSL_ENABLE=1

C_OBJECTS=$(addprefix $(OBJDIR)/,$(SOURCES:.c=.o))
OBJECTS=$(C_OBJECTS)

DEPS=$(addprefix $(DEPDIR)/, $(SOURCES:.c=.d))

INCS=$(addprefix -I, $(INCLUDE_PATHS))

LIBS=$(addprefix -L, $(LIBRARY_PATHS))
LIBS+=$(addprefix -l, $(LIBRARIES))

OBJDIR:=$(TARGET_ARCH)/objs
DEPDIR:=$(TARGET_ARCH)/deps
BINDIR:=$(TARGET_ARCH)/bin
DATADIR=$(TARGET_ARCH)/share/$(EXENAME)

EXENAME:=miniweb

all $(EXENAME): $(BINDIR)/$(EXENAME)

clean: 
	@echo Cleaning
	$(V)rm -rf $(OBJDIR) $(DEPDIR) $(LIBDIR)

clean-clear: clean
	@echo Cleaning Clear

distclean: clean-clear
	@echo Dist-cleaning
	$(V)rm -rf $(TARGET_ARCH)

run-tests: $(EXENAME) $(TESTDATA)
	@echo Running $(EXENAME)
	$(V)$(BINDIR)/$(EXENAME)

$(OBJDIR):
	$(V)mkdir -p $(OBJDIR)

$(DEPDIR):
	$(V)mkdir -p $(DEPDIR)

$(BINDIR):
	$(V)mkdir -p $(BINDIR)

$(OBJDIR)/%.o: %.c 
	@echo Compiling $(notdir $<)
	$(V)$(MAKEDEPEND)
	$(V)$(CC) $(CFLAGS) $(DEFS) $(INCS) -c $< -o $@

$(BINDIR)/$(EXENAME): $(BINDIR) $(OBJDIR) $(DEPDIR) $(OBJECTS)
	@echo Linking $(notdir $@)
	$(V)$(CC) $(CFLAGS) $(DEFS) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

.PHONY: $(EXENAME)
.PHONY: all clean clean-clear distclean

-include $(DEPS)
