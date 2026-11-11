#!/usr/bin/env bash

# Run the .cocci files in the tests directory; these act
# as a blacklist.
#
# A semantic patch can come with a .sample file of code that it has to
# flag on exactly the lines marked MUST-FLAG, so that one which no longer
# matches anything (e.g. with a different version of spatch) is noticed
# instead of passing.

set -euo pipefail

. $(dirname $0)/libtest.sh

if ! spatch --version 2>/dev/null; then
    skip "no spatch; get it from http://coccinelle.lip6.fr/"
fi

if test -z "${OSTREE_UNINSTALLED_SRCDIR:-}"; then
    skip "running installed?"
fi

coccitests=$(ls $(dirname $0)/coccinelle/*.cocci)
echo "1.."$(echo ${coccitests} | wc -w)

for cocci in $(dirname $0)/coccinelle/*.cocci; do
    echo "Running: ${cocci}"
    sample=${cocci%.cocci}.sample
    if test -f ${sample}; then
        cp ${sample} sample.c
        spatch --very-quiet ${cocci} sample.c > cocci-sample.out
        grep -F -e MUST-FLAG sample.c > sample-expected.txt
        sed -n -e '/^---/d' -e 's/^-//p' cocci-sample.out > sample-flagged.txt
        if ! diff -u sample-expected.txt sample-flagged.txt >&2; then
            fatal "Semantic patch does not flag exactly the marked lines of ${sample}"
        fi
        rm sample.c
    fi
    spatch --very-quiet --dir ${OSTREE_UNINSTALLED_SRCDIR} ${cocci} > cocci.out
    if test -s cocci.out; then
        sed -e 's/^/# /' < cocci.out >&2
        fatal "Failed semantic patch: ${cocci}"
    fi
    echo ok ${cocci}
done
