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

ifndef	WINDOWS_MK_INCLUDED
WINDOWS_MK_INCLUDED := true
	
CC = cl
LINK = link
RC = rc
SHARED = /DLL

CFLAGS  += /O2 /Oi /GL /Gy /GT /D _CRT_SECURE_NO_WARNINGS /wd4996 /wd4101 /wd4244 /wd4995 /wd4275 \
	/EHa /nologo /Zi /errorReport:none /MP /Gm- /W3 /c /TC /D WIN32 /D _WIN32 /D ZLIB_WINAPI /D PCRE_STATIC

LDFLAGS += /SUBSYSTEM:CONSOLE /NOLOGO /INCREMENTAL:NO /errorReport:none /MANIFEST:NO \
	/OPT:REF /OPT:ICF /LTCG /DYNAMICBASE /NXCOMPAT /DEBUG
	
LIBS = kernel32.lib user32.lib ws2_32.lib crypt32.lib advapi32.lib shlwapi.lib shell32.lib

$(IIS_OUT_OBJS): COMPILEOPTS += /TP
$(TEST_OBJECTS): CFLAGS += /D HAVE_MSVC_THREAD_LOCAL_STORAGE /D HAVE__SNPRINTF_S /D HAVE__VSNPRINTF_S /D UNIT_TESTING_DEBUG=1
	
ifdef 64
 LDFLAGS += /MACHINE:X64
 OS_MARCH := _64
 CFLAGS += /D ADMIN64BIT
else
 LDFLAGS += /MACHINE:X86
 OS_MARCH :=
endif

ifdef DEBUG
 CFLAGS += /MTd /D _DEBUG /D DEBUG
else
 CFLAGS += /MT
endif
	
libopenam: $(OUT_OBJS)
	@$(ECHO) "[*** Creating "$@" shared library ***]"
	-$(RMALL) $(OBJDIR)$(PS)version.*
	$(SED) -e "s$(SUB)_FILE_NAME_$(SUB)libopenam.dll$(SUB)g" \
	       -e "s$(SUB)_FILE_TYPE_$(SUB)VFT_DLL$(SUB)g" < source$(PS)version.rc.template > $(OBJDIR)$(PS)version.rc
	$(RC)  /l 0x0409 /nologo /fo $(OBJDIR)$(PS)version.res $(OBJDIR)$(PS)version.rc
	${LINK} $(SHARED) $(LDFLAGS) $(OUT_OBJS) $(OBJDIR)$(PS)version.res /OUT:build\$@.dll /PDB:build\$@.pdb \
	    $(LIBS)
	
apache: $(OUT_OBJS) $(APACHE_OUT_OBJS)
	@$(ECHO) "[*** Creating "$@" shared library ***]"
	-$(RMALL) $(OBJDIR)$(PS)version.*
	$(SED) -e "s$(SUB)_FILE_NAME_$(SUB)mod_openam.dll$(SUB)g" \
	       -e "s$(SUB)_FILE_TYPE_$(SUB)VFT_DLL$(SUB)g" < source$(PS)version.rc.template > $(OBJDIR)$(PS)version.rc
	$(RC)  /l 0x0409 /nologo /fo $(OBJDIR)$(PS)version.res $(OBJDIR)$(PS)version.rc
	${LINK} $(SHARED) $(LDFLAGS) $(OUT_OBJS) $(APACHE_OUT_OBJS) $(OBJDIR)$(PS)version.res /OUT:build\mod_openam.dll \
	    /PDB:build\mod_openam.pdb $(LIBS) \
	    extlib/$(OS_ARCH)$(OS_MARCH)/apache24/lib/libapr-1.lib extlib/$(OS_ARCH)$(OS_MARCH)/apache24/lib/libaprutil-1.lib \
	    extlib/$(OS_ARCH)$(OS_MARCH)/apache24/lib/libhttpd.lib

apache22: apache22_pre $(OUT_OBJS) $(APACHE22_OUT_OBJS) apache22_post
	@$(ECHO) "[*** Creating "$@" shared library ***]"
	-$(RMALL) $(OBJDIR)$(PS)version.*
	$(SED) -e "s$(SUB)_FILE_NAME_$(SUB)mod_openam.dll$(SUB)g" \
	       -e "s$(SUB)_FILE_TYPE_$(SUB)VFT_DLL$(SUB)g" < source$(PS)version.rc.template > $(OBJDIR)$(PS)version.rc
	$(RC)  /l 0x0409 /nologo /fo $(OBJDIR)$(PS)version.res $(OBJDIR)$(PS)version.rc
	${LINK} $(SHARED) $(LDFLAGS) $(OUT_OBJS) $(APACHE22_OUT_OBJS) $(OBJDIR)$(PS)version.res /OUT:build\mod_openam.dll \
	    /PDB:build\mod_openam.pdb $(LIBS) \
	    extlib/$(OS_ARCH)$(OS_MARCH)/apache22/lib/libapr-1.lib extlib/$(OS_ARCH)$(OS_MARCH)/apache22/lib/libaprutil-1.lib \
	    extlib/$(OS_ARCH)$(OS_MARCH)/apache22/lib/libhttpd.lib
	
iis: $(OUT_OBJS) $(IIS_OUT_OBJS)
	@$(ECHO) "[*** Creating "$@" shared library ***]"
	-$(RMALL) $(OBJDIR)$(PS)version.*
	$(SED) -e "s$(SUB)_FILE_NAME_$(SUB)mod_iis_openam.dll$(SUB)g" \
	       -e "s$(SUB)_FILE_TYPE_$(SUB)VFT_DLL$(SUB)g" < source$(PS)version.rc.template > $(OBJDIR)$(PS)version.rc
	$(RC)  /l 0x0409 /nologo /fo $(OBJDIR)$(PS)version.res $(OBJDIR)$(PS)version.rc
	${LINK} $(SHARED) $(LDFLAGS) $(OUT_OBJS) $(IIS_OUT_OBJS) $(OBJDIR)$(PS)version.res /OUT:build\mod_iis_openam.dll \
	    /PDB:build\mod_iis_openam.pdb $(LIBS) /EXPORT:RegisterModule oleaut32.lib

varnish: 
	$(error Varnish target is not supported on this platform)

varnish3: 
	$(error Varnish target is not supported on this platform)
	
agentadmin: $(OUT_OBJS) $(ADMIN_OUT_OBJS)
	@$(ECHO) "[*** Creating "$@" binary ***]"
	-$(RMALL) $(OBJDIR)$(PS)version.*
	$(SED) -e "s$(SUB)_FILE_NAME_$(SUB)agentadmin.exe$(SUB)g" \
	       -e "s$(SUB)DESCRIPTION$(SUB)\"OpenAM Web Agent Administration Utility\"$(SUB)g" \
	       -e "s$(SUB)_FILE_TYPE_$(SUB)VFT_APP$(SUB)g" < source$(PS)version.rc.template > $(OBJDIR)$(PS)version.rc
	$(RC)  /l 0x0409 /nologo /fo $(OBJDIR)$(PS)version.res $(OBJDIR)$(PS)version.rc
	${LINK} $(LDFLAGS) $(OUT_OBJS) $(ADMIN_OUT_OBJS) $(OBJDIR)$(PS)version.res /OUT:build\$@.exe /PDB:build\$@.pdb \
	    $(LIBS) ole32.lib oleaut32.lib ahadmin.lib

tests: clean build version test_includes $(OUT_OBJS) $(TEST_OBJECTS) 
	@$(ECHO) "[***** Building "$@" binary *****]"
	-$(RMALL) $(OBJDIR)$(PS)version.*
	$(SED) -e "s$(SUB)_FILE_NAME_$(SUB)test.exe$(SUB)g" \
	       -e "s$(SUB)DESCRIPTION$(SUB)\"OpenAM Web Agent Test Utility\"$(SUB)g" \
	       -e "s$(SUB)_FILE_TYPE_$(SUB)VFT_APP$(SUB)g" < source$(PS)version.rc.template > $(OBJDIR)$(PS)version.rc
	$(RC)  /l 0x0409 /nologo /fo $(OBJDIR)$(PS)version.res $(OBJDIR)$(PS)version.rc
	${LINK} $(LDFLAGS) $(OUT_OBJS) $(TEST_OBJECTS) $(OBJDIR)$(PS)version.res /OUT:build$(PS)test.exe $(LIBS)
	
endif
