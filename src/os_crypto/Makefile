# Makefile for os_crypto
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT=../
NAME=os_crypto

include ../Config.Make

os_crypto:
		make -C blowfish
		make -C md5 
		make -C sha1 
		make -C md5_sha1 
		make -C shared 
		${BUILDLIB} os_crypto.a blowfish/bf_op.o blowfish/bf_skey.o blowfish/bf_enc.o md5/md5_op.o md5/md5.o sha1/sha1_op.o md5_sha1/md5_sha1_op.o shared/*.o

clean:
		make -C blowfish clean
		make -C md5 clean
		make -C sha1 clean
		make -C md5_sha1 clean
		make -C shared clean
		${CLEAN}
