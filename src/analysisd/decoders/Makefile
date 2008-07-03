# Makefile for the decoders
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net

PT=../../
NAME=ossec-analysisd

include ../../Config.Make


dc:
		cd plugins; make;
		$(CC) $(CFLAGS) -I../ -c $(SOURCES)
		ar cru decoders.a $(OBJECTS) plugins/*.o
		ranlib decoders.a

logtest:
		cd plugins; make;
		$(CC) $(CFLAGS) -DTESTRULE -I../ -c $(SOURCES)
		ar cru decoders.a $(OBJECTS) plugins/*.o
		ranlib decoders.a

clean:
		cd plugins; make clean;
		-${CLEAN}
