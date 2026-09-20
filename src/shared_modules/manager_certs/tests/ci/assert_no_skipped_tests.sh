#!/bin/sh
# assert_no_skipped_tests.sh — the manager_certs suite has to RUN, not report success for cases it
# never executed.
#
# Why this exists. 59 of the suite's 84 GTest cases need a root-owned lock file (G0/C36f) and skip
# themselves without euid 0, and both shell suites skip their writing half the same way. GitHub's
# runners are not root, so `ctest` came back green with 25 cases run out of 84 — the atomic write,
# the lock, the guards, the C29 invariant and the whole component suite never executed, and the job
# was green anyway. The missing `sudo` was the smaller half of that failure: the larger half is that
# nobody could tell from the outside. Running the tests elevated fixes today; this fixes tomorrow,
# by making "the suite skipped cases" a red job instead of an invisible one.
#
# Reads a `ctest -V` log (verbose, so every case's own output is in it) and fails when any case was
# skipped, naming how many and which. It also refuses a log that carries no GoogleTest summary at
# all, which is what a future `ctest` call without -V would produce: a check that cannot see the
# cases must not pass for lack of evidence.
#
# Usage: assert_no_skipped_tests.sh <ctest -V log>
# Exit:  0 nothing was skipped · 1 something was · 2 the log cannot answer the question.

set -u

log="${1:-}"
if [ -z "$log" ] || [ ! -r "$log" ]; then
    echo "usage: $0 <ctest -V log>" >&2
    exit 2
fi

awk '
    {
        line = $0
        # ctest -V prefixes every line a test writes with "<test number>: ".
        sub(/^[ \t]*[0-9]+: /, "", line)
    }

    # "[  PASSED  ] 84 tests." — the proof that this log really carries the suites own output.
    line ~ /^\[ *PASSED *\] [0-9]+ tests?\./ {
        summaries++
        count = line
        sub(/^\[ *PASSED *\] /, "", count)
        sub(/ .*$/, "", count)
        passed += count + 0
        next
    }

    # "[  SKIPPED ] 59 tests, listed below:" — the count GoogleTest itself reports.
    line ~ /^\[ *SKIPPED *\] [0-9]+ tests?,/ {
        count = line
        sub(/^\[ *SKIPPED *\] /, "", count)
        sub(/ .*$/, "", count)
        skipped += count + 0
        next
    }

    # "[  SKIPPED ] Suite.Case" (the summary listing) and "[  SKIPPED ] Suite.Case (0 ms)" (the
    # case itself): the same name twice, so they are deduplicated.
    line ~ /^\[ *SKIPPED *\] / {
        name = line
        sub(/^\[ *SKIPPED *\] /, "", name)
        sub(/ \(.*$/, "", name)
        if (!(name in seen)) { seen[name] = 1; names[++total] = name }
        next
    }

    # The two shell suites report their own: "  skip <case>: <reason>".
    line ~ /^[ \t]*skip [^:]+:/ {
        name = line
        sub(/^[ \t]*skip /, "", name)
        shell++
        if (!(name in seen)) { seen[name] = 1; names[++total] = name }
        next
    }

    END {
        if (summaries == 0) {
            print "----------------------------------------"
            print "FAILED: this log carries no GoogleTest summary, so it cannot show whether cases were"
            print "        skipped. Is ctest still being run with -V?"
            print "----------------------------------------"
            exit 2
        }

        missed = skipped + shell
        if (missed == 0) {
            print "----------------------------------------"
            printf "PASSED: %d GoogleTest case(s) passed and nothing in this log was skipped\n", passed
            print "----------------------------------------"
            exit 0
        }

        print "----------------------------------------"
        printf "FAILED: %d case(s) were SKIPPED, so the job is green over tests that never ran:\n", missed
        for (i = 1; i <= total; i++) { print "  - " names[i] }
        print ""
        print "The manager_certs suite needs euid 0 (its lock file has to be root-owned, G0/C36f)."
        print "Run ctest elevated, or fix whatever else made these cases opt out."
        print "----------------------------------------"
        exit 1
    }
' "$log"
