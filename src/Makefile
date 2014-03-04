# Makefile
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

none:
		@echo "Nothing selected ..."
		@echo "\"make all\" to compile everything."
		@echo "\"make server\" to build the server."
		@echo "\"make local\" to build the local."
		@echo "\"make agent\" to build the agent."
		@echo "\"make libs\" to build the libraries only."
		@echo "\"make clean\" to clean anything built."
		@echo "\"make setagent\" to set agent install."
		@echo "\"make setlocal\" to set local install."
		@echo "\"make setclang\" to use clang for building ossec."
		@echo "\"make unsetclang\" to use gcc for building ossec."
		@echo "\"make setprelude\" to enable prelude output."
		@echo "\"make setdb\" to enable database support."
		@echo "\"make unsetdb\" to disable database support."
		@echo "\"make setoneway\" to enable one-way connection to the manager."
		@echo "\"make setgeoip\" to enable source IP geolocalization."

clean:
		@/bin/sh ./Makeall clean
		rm -f ../bin/*
		rmdir ../bin/
		rm -f isbigendian
		rm -rf win-pkg/
		rm -f Config.OS
		rm -f win32/LICENSE.txt
		rm -f win32/help_win.txt
		rm -f win32/internal_options-win.conf
		rm -f win32/ossec-win.conf
		rm -f win32/restart-ossec.cmd
		rm -f win32/route-null.cmd

all:
		@/bin/sh ./Makeall all

build:
		@/bin/sh ./Makeall build

libs:
		@/bin/sh ./Makeall libs

server:
		@/bin/sh ./InstallServer.sh

local:
		@/bin/sh ./InstallServer.sh local

agent:
		@/bin/sh ./InstallAgent.sh

windows_agent:
		( cd win32 && /bin/sh ./gen_win.sh )
		( cd win-pkg && /bin/sh ./make.sh )
        
setagent:
		@echo "CEXTRA=-DCLIENT" >> ./Config.OS

setclang:
		@mv LOCATION LOCATION.backup
		@sed -e "s/^CC=.*/CC=clang/g" LOCATION.backup > LOCATION
		@rm LOCATION.backup

unsetclang:
		@mv LOCATION LOCATION.backup
		@sed -e "s/^CC=.*/CC=gcc/g" LOCATION.backup > LOCATION
		@rm LOCATION.backup

setprelude:
		@echo "CPRELUDE=-DPRELUDE -lprelude `libprelude-config --pthread-cflags` `libprelude-config --libs`" >> ./Config.OS

setgeoip:
		@echo "CGEOIP=-DGEOIP" >> ./Config.OS
		@echo "CGEOIPLIB=-I/usr/local/include -L/usr/local/lib -lGeoIP" >> ./Config.OS

setdb:
		@cd ./os_dbd; echo "CDB=`./dbmake.sh`" >> ../Config.OS;
setmaxagents:
		@/bin/sh ./Makeall setmaxagents
unsetdb:
		@echo "CDB=" >> ./Config.OS;
setlocal:
		@echo "CEXTRA=-DLOCAL" >> ./Config.OS

setfullsubject:
		@echo "FEXTRA=-DCLEANFULL" >> ./Config.OS

setoneway:
		@echo "FEXTRA=-DONEWAY" >> ./Config.OS

setzeromq:
		@echo "CZEROMQ_OUTPUT=-DZEROMQ_OUTPUT -lzmq -lczmq" >> ./Config.OS
