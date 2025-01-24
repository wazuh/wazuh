#! /bin/bash
# September 13, 2021
#
# Supports 4.8.0+ source

# build <server|agent|winagent>
build() {
    [ -n "$1" ]

    >&2 echo "INFO: Building $1 => $folder/src/build-$1.log"

    {
        find external/* > /dev/null 2>&1 || make deps TARGET=$1
        make clean-internals
        make TARGET=$1 DEBUG=1 TEST=1 $jobsopt
    } > build-$1.log 2>&1
}

clean-build() {
    make clean-deps
    rm -rf external/*
    make clean
}

run-ctest() {
    >&2 echo "INFO: Running ctest => $folder/src/ctest.log"
    ctest --test-dir build --output-on-failure 2> ctest.log
}

# cmocka-tests <server|agent|winagent>
cmocka-tests() {
    [ -n "$1" ]

    >&2 echo "INFO: Running $1 cmocka tests => $folder/src/cmocka-tests-$1.log"

    if [ "$1" = "winagent" ]
    then
        toolchainopt="-DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake"
    fi

    {
        rm -rf unit_tests/build
        mkdir -p unit_tests/build
        cd unit_tests/build
        cmake -DTARGET=$1 $toolchainopt ..
        make $jobsopt
    } > cmocka-tests-$1.log 2>&1

    if [ "$1" = "winagent" ]
    then
        WINEARCH="win32" WINEPATH="/usr/i686-w64-mingw32/lib;$(realpath $(pwd)/../..)" ctest
    else
        make coverage
    fi 2>> cmocka-tests-$1.log

    {
        cd ../..
        rm -r unit_tests/build
    } >&2
}

rtr() {
    [ -n "$1" ]

    python3 build.py -r $1
}

# print-ctest <result file>
print-ctest() {
    [ -n "$1" ]

    echo -e "## Unit tests\n\n|Test|Status|\n|---|:-:|"
    sed -En 's- *[[:digit:]]+/[[:digit:]]+ Test +#[[:digit:]]+: ([[:graph:]]+) \.+[ *]+([[:alpha:]]+) +.+-|\1|\2|-p' $1 | sed 's/|Passed|/|🟢|/;s/|Failed|/|🔴|/'
}

# print-cmocka-tests <title> <result file>
print-cmocka-tests() {
    [ -n "$1" ]
    [ -n "$2" ]

    echo -e "## $1\n\n### Tests\n\n|Test|Status|\n|---|:-:|"
    sed -En 's- *[[:digit:]]+/[[:digit:]]+ Test +#[[:digit:]]+: ([[:graph:]]+) \.+[ *]+([[:alpha:]]+) +.+-|\1|\2|-p' $2 | sed 's/|Passed|/|🟢|/;s/|Failed|/|🔴|/'

    if grep "Summary coverage rate:" $2 > /dev/null
    then
        echo -e "\n### Coverage\n\n|Coverage type|Percentage|Result|\n|---|---|---|"
        sed -En 's/ +([[:alpha:]])([[:alpha:]]+)\.+: ([[:digit:]]+\.[[:digit:]]+%) \(([[:print:]]+)\)/|\U\1\L\2|\3|\4|/p' $2
    fi
}

# print-rtr <title> <result file>
print-rtr() {
    [ -n "$1" ]
    [ -n "$2" ]

    echo -e "## $1\n\n### Tests\n\n|Test|Status|\n|---|:-:|"

    sed -En 's/\x1b\[[0-9;]*m//g;s/^ ?\[(Cppcheck): ([[:alpha:]]+)\]/|\1|\2|/p' $2 | sed 's/|PASSED|/|🟢|/;s/|FAILED|/|🔴|/'
    sed -En '/= Running Tests/,/= Running (Coverage|Valgrind)/p' $2 | sed -En 's/\x1b\[[0-9;]*m//g;s/^ ?\[([[:print:]]+): ([[:alpha:]]+)\]/|\1|\2|/p' | sed 's/|PASSED|/|🟢|/;s/|FAILED|/|🔴|/'

    echo -e "\n### Coverage\n\n|Coverage type|Percentage|Result|\n|---|---|---|"
    sed -En 's/\x1b\[[0-9;]*m//g;s/^ ?\[([[:alpha:]]+) Coverage ([[:print:]]+): ([[:alpha:]]+)\]/|\1|\2|\3|/p' $2 | sed 's/|PASSED|/|🟢|/;s/|FAILED|/|🔴|/'
}

print-help() {
    echo \
"Usage: $0 [branch]
    branch  Branch that will be tested. Default: master
Environment variables:
    THREADS Number of parallel jobs. Default: 1
Example:
    THREADS=4 $0 v4.2.1"
}

parse-opts() {
    for i in "$@"
    do
        case $i in
        "-h"|"--help")
            print-help
            exit 0
            ;;
        *)
            branch=$i
        esac
    done

    if [ -z "$branch" ]
    then
        >&2 echo "WARNING: branch undefined. Using master."
        branch=master
    fi

    folder="wazuh-$branch"

    if [ -e "$folder" ]
    then
        >&2 echo "WARNING: Folder $folder already exists."
    fi

    if [ -n "$THREADS" ]
    then
        jobsopt="-j$THREADS"
    fi
}

main() {
    parse-opts "$@"

    {
        if [ ! -d $folder ]
        then
            >&2 echo "INFO: Cloning wazuh/$branch"
            git clone --quiet --depth 1 https://github.com/wazuh/wazuh.git -b $branch $folder > /dev/null || exit
        fi

        cd $folder/src
        build server
    }

    cmocka-tests server > result-cmocka-server.txt
    run-ctest > result-ctest.txt

    declare -A components=( \
        [data_provider]=data_provider \
        [dbsync]=shared_modules/dbsync \
        [rsync]=shared_modules/rsync \
        [syscollector]=wazuh_modules/syscollector\
        [fim]=syscheckd\
    )

    declare -A titles=( \
        [data_provider]="Data provider" \
        [dbsync]="DBsync" \
        [rsync]="Rsync" \
        [syscollector]="Syscollector" \
        [fim]="File integrity monitoring" \
    )

    for i in ${!components[@]}
    do
        >&2 echo "INFO: Running ${components[$i]} RTR toolset => $folder/src/rtr-$i.log"
        rtr ${components[$i]} > result-$i.txt 2> rtr-$i.log
    done

    build agent
    cmocka-tests agent > result-cmocka-agent.txt

    {
        clean-build > /dev/null 2>&1
        build winagent
    }

    cmocka-tests winagent > result-cmocka-winagent.txt

    for i in ${!components[@]}
    do
        print-rtr "${titles[$i]}" result-$i.txt
        echo
    done

    declare -A titles=( \
        [server]="Linux Manager cmocka tests" \
        [agent]="Linux agent cmocka tests" \
        [winagent]="Windows agent cmocka tests" \
    )

    print-ctest result-ctest.txt
    echo

    for i in ${!titles[@]}
    do
        print-cmocka-tests "${titles[$i]}" result-cmocka-$i.txt
        echo
    done
}

set -e

if ! main "$@"
then
    >&2 echo "ERROR: The procedure failed."
    exit 1
fi
