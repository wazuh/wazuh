#!/bin/sh

echo "Starting log unit tests (must be run as root and on a system with OSSEC installed)."
echo "(it will make sure the current rules aree working as they should)."
rm -f ./tmpres
for i in ./*/log; do
    idir=`dirname $i`

    rm -f ./tmpres || exit "Unable to remove tmpres.";
    cat $i | /var/ossec/bin/ossec-logtest 2>&1|grep -v ossec-testrule |grep -A 500 "Phase 1:" > ./tmpres

    if [ ! -f $idir/res ]; then
        echo "** Creating entry for $i - Not set yet."
        cat ./tmpres > $idir/res
        rm -f tmpres
        continue;
    fi
    MD1=`md5sum ./tmpres | cut -d " " -f 1`
    MD2=`md5sum $idir/res | cut -d " " -f 1`

    if [ ! $MD1 = $MD2 ]; then
        echo "**ERROR: Unit testing failed. Output for the test $i failed."
        echo "== OLD OUTPUT: =="
        cat $idir/res
	echo "== NEW OUTPUT: =="
        cat tmpres
        echo "** ERROR: Exiting."
        rm -f tmpres
        exit 0;
    fi

done

echo ""
echo "Log unit tests completed. Everything seems ok (nothing changed since last test regarding the outputs)."
