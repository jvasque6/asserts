#!/usr/bin/env/bash

function striprun {
    python3 "$1" |
    perl -pe 's/\e([^\[\]]|\[.*?[a-zA-Z]|\].*?\a)//g' |
    tee "$1".out
}

export -f striprun
# Execute the examples and save their output
find sphinx/source/example/ -name '*.py' -exec sh -c 'striprun $1' _ {} \;

# HTML must go to public/ for gitlab pages
mkdir -p public/
# Generate e: separate page per module f: overwrite M: module doc first
sphinx-apidoc -efM fluidasserts -o sphinx/source
# Get version from build/dist zip
VER=$(find /builds/fluidsignal/asserts/build/dist/ |\
      sed 's_fluidasserts-\|.zip__g')
CHECKS=$(grep -rI fluidasserts -e '@track' | wc -l)
sed -i "s/<CHECKS>/$CHECKS/" sphinx/source/index.rst
sphinx-build -D version="v.$VER" -D release="v.$VER" \
             -a sphinx/source/ public/
sphinx-build -b linkcheck sphinx/source public/review/
sphinx-build -b coverage  sphinx/source public/review/
