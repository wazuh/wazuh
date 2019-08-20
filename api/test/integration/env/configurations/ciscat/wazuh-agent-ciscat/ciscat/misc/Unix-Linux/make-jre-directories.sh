#!/bin/bash

make_jre_directories()
{

        JRES_DIR=jres

        DISTROS='RedHat CentOS SUSE Debian Ubuntu Linux HPUX AIX OSX Solaris'

        if [ -e "$JRES_DIR" -a -d "$JRES_DIR" ]; then
                echo "Directory '$JRES_DIR' already exists - continuing."
        else                
                mkdir "$JRES_DIR";

                if [ $? -eq 1 ]; then
                        echo "ERROR: Unable to create directory '$JRES_DIR'. Ensure you have write permission on the current directory.";
                        exit 1;
                else
                        echo "Created directory '$JRES_DIR'."        
                fi                       
        fi

        for d in $DISTROS; do 

                if [ -e "$JRES_DIR/$d" ]; then
                        echo "Directory '$JRES_DIR/$d' already exists - continuing."
                        continue;
                else
                        mkdir "$JRES_DIR/$d"                        

                        if [ $? -eq 1 ]; then
                                echo "ERROR: Unable to create directory '$JRES_DIR/$d'. Ensure you have write permission on '$JRES_DIR'.";
                                exit 1;
                        else
                                echo "Created directory '$JRES_DIR/$d'."        
                        fi
                fi                               
        done
}
