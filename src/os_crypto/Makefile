# Makefile for os_crypto
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/c/os_crypto/

PT=../
NAME=os_crypto

include ../Config.Make

os_crypto:
		@cd blowfish; make
		@cd md5; make 
		@cd shared; make 
		ar cru os_crypto.a blowfish/bf_op.o blowfish/bf_skey.o blowfish/bf_enc.o md5/md5_op.o md5/md5.o shared/sec.o
		ranlib os_crypto.a
clean:
		@cd blowfish; make clean
		@cd md5; make clean;
		@cd shared; make clean;
		rm -f *.a
