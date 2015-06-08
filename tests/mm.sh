#!/bin/bash

# The contents of this file are subject to the terms of the Common Development and                                                                                     
# Distribution License (the License). You may not use this file except in compliance with the                                                                          
# License.                                                                                                                                                             
#                                                                                                                                                                      
# You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the                                                                                  
# specific language governing permission and limitations under the License.                                                                                            
#                                                                                                                                                                      
# When distributing Covered Software, include this CDDL Header Notice in each file and include                                                                         
# the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL                                                                              
# Header, with the fields enclosed by brackets [] replaced by your own identifying                                                                                     
# information: "Portions copyright [year] [name of copyright owner]".                                                                                                  
#                                                                                                                                                                      
# Copyright 2015 ForgeRock AS.

# This script "makes main", i.e. it builds the test harness test_MAIN.c from the assembled headers
# (it assumes "mh.sh" has already been run).

error=0
verbose=0
OUTPUT=test_MAIN.c

while getopts ':v-:' arg "$@"; do
  case $arg in
    v)  verbose=1 ;;
    ?)  error=1 ;;
  esac
done

let x=OPTIND-1
shift $x

if (( error )); then
    echo "Make a test main $OUTPUT by ingesting the header files and spitting out C source code."
    echo "Usage: $(basename $0) [header1.h [header2.h...]]"
    exit 9
fi

if (( $# == 0 )); then
    set -- *.h
    if (( $# == 1 )) && [[ $1 == '*.h' ]]; then
        echo "No header files found in the current directory."
        echo "cd to the directory containing the unit tests and try again."
        exit 9
    fi
fi
[[ -f $OUTPUT ]] && rm -f $OUTPUT

YEAR=$(date +%Y)
cat > $OUTPUT <<EOF
/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright $YEAR ForgeRock AS.
 */

/** THIS FILE AUTOMATICALLY GENERATED FROM $(basename $0).  DO NOT EDIT !! */

#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "am.h"

EOF

count=0
for header; do
    case $header in
        *.h)   (( count++ )) ;;
        *)     echo "Expected a header file name, got $header, ignoring"
               continue ;;
    esac
    echo "#include \"$header\"" >> $OUTPUT
done

if (( count == 0 )); then
    echo "No header files processed, giving up..."
    exit 6
fi

cat >> $OUTPUT <<EOF

/**
 * The main framework for calling the cmocka tests.  The exit status reflects the success or failure of
 * the tests.
 */
int main(void) {
    const struct CMUnitTest tests[] = {
EOF

LIST=
for header; do
    grep "^void " $header | while read type rest extras; do
        rest=$(echo "$rest" | sed -e 's/(.*//')

        if grep -q "cmocka_unit_test($rest)" $OUTPUT; then
            echo "ERROR: the function $rest in $header is not unique"
            rm $OUTPUT
            exit 99
        fi

        echo "        cmocka_unit_test($rest)," >> $OUTPUT
    done
done

cat >> $OUTPUT <<EOF
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
EOF
