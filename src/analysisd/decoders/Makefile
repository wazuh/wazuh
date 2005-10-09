# Makefile for the decoder plugins 
# Daniel B. Cid <dcid@sourcefire.com>||<daniel.cid@gmail.com>
# http://www.ossec.net/hids/

PT=../../
NAME=ossec-analysisd

include ../../Config.Make


plugins:
		$(CC) $(CFLAGS) -I../ -c $(SOURCES)
		ar cru decoders.a $(OBJECTS)
		ranlib decoders.a

clean:
		-${CLEAN}
