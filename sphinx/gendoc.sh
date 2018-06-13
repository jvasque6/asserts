#!/usr/bin/env/bash

find sphinx/source/example/ -name '*.py' -exec sh -c \
 "python3 {$1} | perl -pe 's/\e([^\[\]]|\[.*?[a-zA-Z]|\].*?\a)//g' > {$1}.out"\
 x {} \;

python sphinx/source/example/qstart-sqli-open.py | \
       perl -pe 's/\e([^\[\]]|\[.*?[a-zA-Z]|\].*?\a)//g' \
       > sphinx/source/example/qstart-sqli-open.out
# HTML must go to public/ for gitlab pages
mkdir -p public/
# Generate e: separate page per module f: overwrite M: module doc first
sphinx-apidoc -efM fluidasserts -o sphinx/source
# Get version from build/dist zip
VER=$(ls /builds/fluidsignal/asserts/build/dist/ |\
      sed 's_fluidasserts-\|.zip__g')
sphinx-build -D version="v.$VER" -D release="v.$VER" \
             -a sphinx/source/ public/
sphinx-build -b linkcheck sphinx/source public/review/
sphinx-build -b coverage  sphinx/source public/review/
