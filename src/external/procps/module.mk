# This file gets included into the main Makefile, in the top directory.

# Ideally, we want something like this:
#
# /lib/libproc.so.w        ELF soname ('w' is a digit, starting from 1)
# /lib/procps-x.y.z.so     file itself (x.y.z is the procps version)
# /lib/libproc.so          for linking, UNSUPPORTED
# /usr/lib/libproc.a       for linking, UNSUPPORTED
# proc/libproc.so.w        as above, if testing with LD_LIBRARY_PATH
# proc/whatever            if testing with LD_PRELOAD
# proc/libproc.a           for static build
#
# Without a stable ABI, there's no point in having any of that.
# Without a stable API, there's no point in having the *.a file.
#
# A new ELF soname is required for every big ABI change. To conserve
# numbers for future use, the ELF soname can be set equal to the
# file name until some future date when a stable ABI is declared.

SHARED     := 1

# for lib$(NAME).so and /usr/include/($NAME) and such
NAME       :=  proc

LIBVERSION := $(VERSION).$(SUBVERSION).$(MINORVERSION)
ABIVERSION := 0

SOFILE     := lib$(NAME)-$(LIBVERSION).so
ifneq ($(ABIVERSION),0)
SOLINK     := lib$(NAME).so
SONAME     := lib$(NAME).so.$(ABIVERSION)
else
SONAME     := $(SOFILE)
SOLINK     := $(SOFILE)
endif

ANAME      := lib$(NAME).a

############

FPIC       := -fpic

ifeq ($(SHARED),1)
ALL        += proc/$(SONAME)
INSTALL    += ldconfig
LIBFLAGS   := -DSHARED=1 $(FPIC)
# This is in gcc 3.5, but exported functions must be marked.
#LIBFLAGS += $(call check_gcc,-fvisibility=hidden,)
LIBPROC    := proc/$(SONAME)
else
ALL        += proc/$(ANAME)
#INSTALL    += $(usr/lib)$(ANAME)
LIBFLAGS   := -DSHARED=0
LIBPROC    := proc/$(ANAME)
endif

LIBSRC :=  $(wildcard proc/*.c)
LIBHDR :=  $(wildcard proc/*.h)
LIBOBJ :=  $(LIBSRC:.c=.o)

# Separate rule for this directory, to use -fpic or -fPIC
$(filter-out proc/version.o,$(LIBOBJ)): proc/%.o: proc/%.c
	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) $(LIBFLAGS) $< -o $@

LIB_X := COPYING module.mk library.map
TARFILES += $(LIBSRC) $(LIBHDR) $(addprefix proc/,$(LIB_X))


# Clean away all output files, .depend, and symlinks.
# Use wildcards in case the version has changed.
CLEAN += proc/.depend proc/lib*.so* proc/lib*.a $(LIBOBJ)
DIRS  += proc/

proc/$(ANAME): $(LIBOBJ)
	$(AR) rcs $@ $^

#proc/$(SONAME): proc/library.map
proc/$(SONAME): $(LIBOBJ)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -shared -Wl,-soname,$(SONAME) -Wl,--version-script=proc/library.map -o $@ $^ -lc


# AUTOMATIC DEPENDENCY GENERATION -- GCC AND GNUMAKE DEPENDENT
proc/.depend: $(LIBSRC) $(LIBHDR)
	$(strip $(CC) $(ALL_CPPFLAGS) $(LIB_CFLAGS) -MM -MG $(LIBSRC) > $@)

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),tar)
ifneq ($(MAKECMDGOALS),extratar)
ifneq ($(MAKECMDGOALS),beta)
-include proc/.depend
endif
endif
endif
endif

#################### install rules ###########################

$(lib)$(SOFILE) : proc/$(SONAME)
	$(install) --mode a=rx $< $@

ifneq ($(SOLINK),$(SOFILE))
.PHONY: $(lib)$(SOLINK)
$(lib)$(SOLINK) : $(lib)$(SOFILE)
	cd $(lib) && $(ln_sf) $(SOFILE) $(SOLINK)
endif

ifneq ($(SONAME),$(SOFILE))
.PHONY: $(lib)$(SONAME)
$(lib)$(SONAME) : $(lib)$(SOFILE)
	cd $(lib) && $(ln_sf) $(SOFILE) $(SONAME)
endif

.PHONY: ldconfig
ldconfig : $(lib)$(SONAME) $(lib)$(SOLINK)
	$(ldconfig)

$(usr/lib)$(ANAME) : proc/$(ANAME)
	$(install) --mode a=r $< $@

# Junk anyway... supposed to go in /usr/include/$(NAME)
#INSTALL += $(addprefix $(include),$(HDRFILES))
#
#$(addprefix $(include),$(HDRFILES)): $(include)% : proc/%
#$(include)% : proc/%
#	$(install) --mode a=r $< $@

##################################################################

proc/version.o:	proc/version.c proc/version.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) $(LIBFLAGS) -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\" -c -o $@ $<
