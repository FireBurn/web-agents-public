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

# This script "makes headers" for the unit test in the specified .c source files.

error=0
verbose=0

while getopts ':v-:' arg "$@"; do
  case $arg in
    v)  verbose=1 ;;
    ?)  error=1 ;;
  esac
done

let x=OPTIND-1
shift $x

if (( error )); then
    echo "Make header files suitable for the the unit tests"
    echo "Usage: $(basename $0) [file.c [file1.c...]]"
    exit 9
fi

if (( $# == 0 )); then
    set -- *.c
    if (( $# == 1 )) && [[ $1 == '*.c' ]]; then
        echo "No arguments and no .c files found in the current directory."
        echo "cd to the directory containing the unit tests and try again."
        exit 18
    fi
fi

for csource; do

    case $csource in
       *test_MAIN.c*) continue ;;
    esac

    suffix="${csource##*.}"
    if [[ $suffix != "c" ]]; then
        echo "$csource: Unknown file suffix .$suffix"
        continue
    fi

    if [[ ! -f $csource ]]; then
        echo "$csource: No such file"
        continue
    fi
    hsource="$(dirname $csource)/$(basename $csource .c).h"

    (( verbose )) && echo "C source: $csource, header: $hsource"

    [[ -f $hsource ]] && rm -f $hsource

    sed -E -n "/ [a-zA-Z0-9_]+\(void *\*\* */p" $csource | while read line; do

       function=$(echo $line | sed -e "s/^[^ ]* //" -e "s/(.*$//")

        (( verbose )) && echo "line $line, defines function $function"

        case $line in
          static*)
            echo "WARNING: function $function in $csource is static"
            ;;
          *)
            if [[ ! -s $hsource ]]; then
                YEAR=$(date +%Y)
                cat > $hsource <<EOF
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

/** This file generated automatically from $(basename $0).  Do not edit. */

EOF
            fi

            echo "void $function(void** state);" >> $hsource

            (( verbose )) && echo "$func matched as test function, added to header"
            ;;
        esac
    done

    rm -f tags
done
