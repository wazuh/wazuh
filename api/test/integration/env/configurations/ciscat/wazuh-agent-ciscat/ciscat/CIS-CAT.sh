#!/bin/sh

JAVA=java
MAX_RAM_IN_MB=768
DEBUG=0

which $JAVA 2>&1 > /dev/null

if [ $? -ne "0" ]; then
        echo "Error: Java is not in the system PATH."
        exit 1
fi

JAVA_VERSION_RAW=`$JAVA -version 2>&1`

echo $JAVA_VERSION_RAW | grep -i 'version' | grep '[1]\.[678]\.[0-9]' 2>&1 > /dev/null

if [ $? -eq "1" ]; then

        echo "Error: The version of Java you are attempting to use is not compatible with CISCAT:"
        echo ""
        echo $JAVA_VERSION_RAW
        echo ""
        echo "You must use Java 1.6.x, 1.7.x, or 1.8.x. The most recent version of Java is recommended."        
        exit 1;
fi

if [ $DEBUG -eq "1" ]; then
	$JAVA -Xmx${MAX_RAM_IN_MB}M -jar CISCAT.jar "$@" --verbose
else
	$JAVA -Xmx${MAX_RAM_IN_MB}M -jar CISCAT.jar "$@"
fi


