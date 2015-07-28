#
# The contents of this file are subject to the terms of the Common Development and
# Distribution License (the License). You may not use this file except in compliance with the
# License.
#
# You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
# specific language governing permission and limitations under the License.
#
# When distributing Covered Software, include this CDDL Header Notice in each file and include
# the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
# Header, with the fields enclosed by brackets [] replaced by your own identifying
# information: "Portions copyright [year] [name of copyright owner]".
#
# Copyright 2014 - 2015 ForgeRock AS.
#

# make options:
#  64=1 builds 64bit binary
#  DEBUG=1 builds debug binary version

64=1
# DEBUG=1

VERSION := 4.0.0-SNAPSHOT

ifneq ("$(PROGRAMFILES)$(ProgramFiles)","")
 OS_ARCH := Windows
 RMALL := cmd /c del /F /Q
 RMDIR := cmd /c rmdir /S /Q
 SED := cmd /c sed.exe
 ECHO := cmd /c echo
 MKDIR := cmd /c mkdir
 CP := cmd /c copy /Y
 CD := cd
 EXEC := 
 REVISION := $(shell svn info . | findstr "Revision:")
 BUILD_MACHINE := $(shell hostname)
 IDENT_DATE := $(shell powershell get-date -format "{dd.MM.yyyy}")
 PATHSEP=\\
 SUB=/
 COMPILEFLAG=/
 COMPILEOPTS=/Fd$@.pdb /Fo$(dir $@)
 OBJ=obj
else
 OS_ARCH := $(shell uname -s)
 OS_MARCH := $(shell uname -m)
 RMALL := rm -fr
 RMDIR := $(RMALL)
 SED := sed
 ECHO := echo
 MKDIR := mkdir -p
 CP := cp
 CD := cd
 EXEC := ./
 REVISION := $(shell svn info . | grep Revision:)
 BUILD_MACHINE := $(shell hostname)
 IDENT_DATE := $(shell date +'%d.%m.%y')
 PATHSEP=/
 SUB=%
 COMPILEFLAG=-
 COMPILEOPTS=-c -o $@
 OBJ=o
endif

SED_ROPT := r
	
ifdef 64
 OS_BITS := _64bit
else
 OS_BITS :=
endif

PS=$(strip $(PATHSEP))

CFLAGS := $(COMPILEFLAG)I.$(PS)source $(COMPILEFLAG)I.$(PS)zlib $(COMPILEFLAG)I.$(PS)expat $(COMPILEFLAG)I.$(PS)pcre \
	  $(COMPILEFLAG)DHAVE_EXPAT_CONFIG_H $(COMPILEFLAG)DHAVE_PCRE_CONFIG_H
OBJDIR := build

APACHE_SOURCES := source/apache/agent.c
APACHE22_SOURCES := source/apache/agent22.c
IIS_SOURCES := source/iis/agent.c
VARNISH_SOURCES := source/varnish/agent.c source/varnish/vcc_if.c
ADMIN_SOURCES := source/admin.c source/admin_iis.c
SOURCES := $(filter-out $(ADMIN_SOURCES), $(wildcard source/*.c)) $(wildcard expat/*.c) $(wildcard pcre/*.c) $(wildcard zlib/*.c)
OBJECTS := $(SOURCES:.c=.$(OBJ))
OUT_OBJS := $(addprefix $(OBJDIR)/,$(OBJECTS))
ADMIN_OBJECTS := $(ADMIN_SOURCES:.c=.$(OBJ))
ADMIN_OUT_OBJS := $(addprefix $(OBJDIR)/,$(ADMIN_OBJECTS))
APACHE_OBJECTS := $(APACHE_SOURCES:.c=.$(OBJ))
APACHE22_OBJECTS := $(APACHE22_SOURCES:.c=.$(OBJ))
APACHE_OUT_OBJS := $(addprefix $(OBJDIR)/,$(APACHE_OBJECTS))
APACHE22_OUT_OBJS := $(addprefix $(OBJDIR)/,$(APACHE22_OBJECTS))
IIS_OBJECTS := $(IIS_SOURCES:.c=.$(OBJ))
IIS_OUT_OBJS := $(addprefix $(OBJDIR)/,$(IIS_OBJECTS))
VARNISH_OBJECTS := $(VARNISH_SOURCES:.c=.$(OBJ))
VARNISH_OUT_OBJS := $(addprefix $(OBJDIR)/,$(VARNISH_OBJECTS))
ifdef TESTS
 TEST_FILES := $(addprefix tests/,$(addsuffix .c,$(TESTS)))
else
 TEST_FILES := $(filter-out test_MAIN.c, $(wildcard tests/*.c))
endif
TEST_SOURCES := $(wildcard cmocka/*.c) $(wildcard tests/*.c)
TEST_OBJECTS := $(addprefix $(OBJDIR)/,$(TEST_SOURCES:.c=.$(OBJ)))

$(APACHE_OUT_OBJS): CFLAGS += $(COMPILEFLAG)Iextlib/$(OS_ARCH)/apache24/include \
	$(COMPILEFLAG)Iextlib/$(OS_ARCH)_$(OS_MARCH)/apache24/include $(COMPILEFLAG)DAPACHE2 $(COMPILEFLAG)DAPACHE24
$(VARNISH_OUT_OBJS): CFLAGS += $(COMPILEFLAG)Iextlib/$(OS_ARCH)/varnish/include
$(APACHE22_OUT_OBJS): CFLAGS += $(COMPILEFLAG)Iextlib/$(OS_ARCH)/apache22/include \
	$(COMPILEFLAG)Iextlib/$(OS_ARCH)_$(OS_MARCH)/apache22/include $(COMPILEFLAG)DAPACHE2
$(TEST_OBJECTS): CFLAGS += $(COMPILEFLAG)I.$(PS)cmocka $(COMPILEFLAG)I.$(PS)tests $(COMPILEFLAG)I.$(PS)$(OBJDIR)$(PS)tests \
	$(COMPILEFLAG)DHAVE_SIGNAL_H
	
ifeq ($(OS_ARCH), Linux)
 include Makefile.linux.mk
endif
ifeq ($(OS_ARCH), SunOS)
 include Makefile.solaris.mk
endif
ifeq ($(OS_ARCH), AIX)
 include Makefile.aix.mk
endif
ifeq ($(OS_ARCH), Darwin)
 include Makefile.macos.mk
 SED_ROPT := E
endif
ifeq ($(OS_ARCH), Windows)
 include Makefile.windows.mk
endif

VERSION_NUM := $(shell $(ECHO) $(VERSION) | $(SED) -$(SED_ROPT) "s/^([.0-9]*)-.*/\1/g" | $(SED) -$(SED_ROPT) "s/\./\,/g")

$(OBJDIR)/%.$(OBJ): %.c
	@$(ECHO) "[*** Compiling "$<" ***]"
	$(CC) $(CFLAGS) $< $(COMPILEOPTS)

.DEFAULT_GOAL := all

all: apachezip

build:
	$(MKDIR) $(OBJDIR)$(PS)expat
	$(MKDIR) $(OBJDIR)$(PS)pcre
	$(MKDIR) $(OBJDIR)$(PS)zlib
	$(MKDIR) $(OBJDIR)$(PS)cmocka
	$(MKDIR) $(OBJDIR)$(PS)tests
	$(MKDIR) log
	$(MKDIR) $(OBJDIR)$(PS)source$(PS)apache
	$(MKDIR) $(OBJDIR)$(PS)source$(PS)iis
	$(MKDIR) $(OBJDIR)$(PS)source$(PS)varnish

version:
	@$(ECHO) "[***** Updating version.h *****]"
	-$(RMALL) source$(PS)version.h
	$(SED) -e "s$(SUB)_REVISION_$(SUB)$(REVISION)$(SUB)g" \
	    -e "s$(SUB)_IDENT_DATE_$(SUB)$(IDENT_DATE)$(SUB)g" \
	    -e "s$(SUB)_BUILD_MACHINE_$(SUB)$(BUILD_MACHINE)$(SUB)g" \
	    -e "s$(SUB)_VERSION_NUM_$(SUB)$(VERSION_NUM)$(SUB)g" \
	    -e "s$(SUB)_VERSION_$(SUB)$(VERSION)$(SUB)g" < source$(PS)version.template > source$(PS)version.h

clean:
	-$(RMDIR) $(OBJDIR)
	-$(RMDIR) log
	-$(RMALL) source$(PS)version.h

test_includes:
	@$(ECHO) "[***** Creating tests.h *****]"
	-$(RMALL) $(OBJDIR)$(PS)tests$(PS)tests.h
	$(SED) -$(SED_ROPT) "/.*static.+/d" $(TEST_FILES) | $(SED) -$(SED_ROPT)n "/.*\(void[ \t]*\*\*[ \t]*state\)/p" | sed -$(SED_ROPT) "s/\{/\;/g" > $(OBJDIR)$(PS)tests$(PS)tests.h.template
	$(CP) $(OBJDIR)$(PS)tests$(PS)tests.h.template $(OBJDIR)$(PS)tests$(PS)tests.h
	$(ECHO) "const struct CMUnitTest tests[] = {" >> $(OBJDIR)$(PS)tests$(PS)tests.h
	$(SED) -$(SED_ROPT)n "s/void (test_.*[^\(])\(.*/cmocka_unit_test(\1),/p" $(OBJDIR)$(PS)tests$(PS)tests.h.template >> $(OBJDIR)$(PS)tests$(PS)tests.h
	$(ECHO) "};" >> $(OBJDIR)$(PS)tests$(PS)tests.h
	$(SED) -ie "s$(SUB)\"$(SUB) $(SUB)g" $(OBJDIR)$(PS)tests$(PS)tests.h

apachezip: CFLAGS += $(COMPILEFLAG)DSERVER_VERSION='"2.4.x"'	
apachezip: clean build version apache agentadmin
	@$(ECHO) "[***** Building Apache 2.4 agent archive *****]"
	-$(MKDIR) $(OBJDIR)$(PS)web_agents
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache24_agent
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)bin
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)lib
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)legal
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)instances
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)log
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)config
	-$(CP) $(OBJDIR)$(PS)agentadmin* $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)bin$(PS)
	-$(CP) $(OBJDIR)$(PS)mod_openam.so $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)lib$(PS)
	-$(CP) $(OBJDIR)$(PS)mod_openam.dll $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)lib$(PS)
	-$(CP) $(OBJDIR)$(PS)mod_openam.pdb $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)lib$(PS)
	-$(CP) config$(PS)* $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)config$(PS)
	-$(CP) legal$(PS)* $(OBJDIR)$(PS)web_agents$(PS)apache24_agent$(PS)legal$(PS)
	$(CD) $(OBJDIR) && $(EXEC)agentadmin --a Apache_v24_$(OS_ARCH)$(OS_BITS)_$(VERSION).zip web_agents

apache22_pre:
	-$(CP) source$(PS)apache$(PS)agent.c source$(PS)apache$(PS)agent22.c

apache22_post:
	-$(RMALL) source$(PS)apache$(PS)agent22.c

apache22zip: CFLAGS += $(COMPILEFLAG)DSERVER_VERSION='"2.2.x"'
apache22zip: clean build version apache22 agentadmin
	@$(ECHO) "[***** Building Apache 2.2 agent archive *****]"
	-$(MKDIR) $(OBJDIR)$(PS)web_agents
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache22_agent
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)bin
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)lib
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)legal
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)instances
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)log
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)config
	-$(CP) $(OBJDIR)$(PS)agentadmin* $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)bin$(PS)
	-$(CP) $(OBJDIR)$(PS)mod_openam.so $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)lib$(PS)
	-$(CP) $(OBJDIR)$(PS)mod_openam.dll $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)lib$(PS)
	-$(CP) $(OBJDIR)$(PS)mod_openam.pdb $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)lib$(PS)
	-$(CP) config$(PS)* $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)config$(PS)
	-$(CP) legal$(PS)* $(OBJDIR)$(PS)web_agents$(PS)apache22_agent$(PS)legal$(PS)
	$(CD) $(OBJDIR) && $(EXEC)agentadmin --a Apache_v22_$(OS_ARCH)$(OS_BITS)_$(VERSION).zip web_agents

iiszip: CFLAGS += $(COMPILEFLAG)DSERVER_VERSION='"7.5, 8.x"'
iiszip: clean build version iis agentadmin
	@$(ECHO) "[***** Building IIS agent archive *****]"
	-$(MKDIR) $(OBJDIR)$(PS)web_agents
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)iis_agent
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)bin
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)lib
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)legal
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)instances
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)log
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)config
	-$(CP) $(OBJDIR)$(PS)agentadmin* $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)bin$(PS)
	-$(CP) $(OBJDIR)$(PS)mod_iis_openam.dll $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)lib$(PS)
	-$(CP) $(OBJDIR)$(PS)mod_iis_openam.pdb $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)lib$(PS)
	-$(CP) config$(PS)* $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)config$(PS)
	-$(CP) legal$(PS)* $(OBJDIR)$(PS)web_agents$(PS)iis_agent$(PS)legal$(PS)
	$(CD) $(OBJDIR) && $(EXEC)agentadmin --a IIS_$(OS_ARCH)$(OS_BITS)_$(VERSION).zip web_agents

varnishzip: CFLAGS += $(COMPILEFLAG)DSERVER_VERSION='"4.0.x"'
varnishzip: clean build version varnish agentadmin
	@$(ECHO) "[***** Building Varnish agent archive *****]"
	-$(MKDIR) $(OBJDIR)$(PS)web_agents
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)varnish_agent
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)bin
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)lib
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)legal
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)instances
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)log
	-$(MKDIR) $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)config
	-$(CP) $(OBJDIR)$(PS)agentadmin* $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)bin$(PS)
	-$(CP) $(OBJDIR)$(PS)libvmod_am.so $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)lib$(PS)
	-$(CP) config$(PS)* $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)config$(PS)
	-$(CP) legal$(PS)* $(OBJDIR)$(PS)web_agents$(PS)varnish_agent$(PS)legal$(PS)
	$(CD) $(OBJDIR) && $(EXEC)agentadmin --a Varnish_v4_$(OS_ARCH)$(OS_BITS)_$(VERSION).zip web_agents
