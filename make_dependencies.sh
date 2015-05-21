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


# Run this script to generate make dependencies if you alter header files to depend on other header files, or if
# you alter source files to depend on other header files.
# Note that we only care about dependencies on header files in the source directory.  We don't really care about
# stuff in /usr/include.

error=0
verbose=0
have_output=0
basename=$(basename $0)

while getopts ':v-:' arg "$@"; do
  case $arg in
    -)  case "$OPTARG" in
           verbose)  verbose=1 ;;
        esac ;;
    v)  verbose=1 ;;
    ?)  error=1 ;;
  esac
done

let x=OPTIND-1
shift $x

if (( error )); then
    echo "Generate:"
    echo "1. dependencies between C source files in the source directory and the header files they include."
    echo "2. dependencies between header files in the source directory and other header files in the source directory."
    echo "Note that the results are output in a form the makefile needs, i.e. with path separators removed and .o"
    echo 'replaced by the makefile defined .$(OBJ)'
    echo "Usage: $basename [-v]"
    echo "       $basename [--verbose]"
    echo "the verbose flags produce mainly meaningless debugging"
    exit 9
fi

#########################################################
# output
#   output the argument, substituting / for $(PS)
#   and .c for .$(OBJ).  No that isn't a typo.
#   .c files depend on .o files.  .o files are .obj
#   files in DOS.
#########################################################
function output() {
    if (( have_output == 0 )); then
        echo "####################################################################################"
        echo "# This section generated by $basename"
        echo "####################################################################################"
        echo "#"
        have_output=1
    fi
    local altered="$@"
    echo $altered | sed -e 's@/@$(PS)@g' -e 's@\.c@.$(OBJ)@'
}


#########################################################
# "main"
#########################################################

# generate a list of the only headers we're interested in
#
source_headers=
for header in $(cd source; find . -name "*.h" -print); do
    header=$(echo $header | sed -e 's@\./@@')
    source_headers="$source_headers|$header"
done
source_headers="$source_headers|"

(( verbose )) && echo "Have source header pattern as: $source_headers" >&2

# now for everything, .c and .h files, figure what depends on what
#
for source in $(find source -name "*.[ch]" -print); do
    dependencies=
    for header in $(sed -n -E -e 's/#include +"([^["]+)"/\1/p' < $source); do

        (( verbose )) && echo "if [[ $source_headers == \"*|$header|*\" ]]" >&2

        if [[ $source_headers != *"|$header|"* ]]; then
            (( verbose )) && echo "rejected dependency from $source to $header" >&2
            continue
        fi
        dependencies="source/$header $dependencies"
    done
    if [[ -n "$dependencies" ]]; then
        output "$source: $dependencies"
    fi
done

if (( have_output )); then
    echo "#"
    echo "####################################################################################"
    echo "# End of section generated by $basename"
    echo "####################################################################################"
fi