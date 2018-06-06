#!/usr/bin/env/bash

mkdir -p public/
sphinx-apidoc -efM fluidasserts -o sphinx/source
VER=$(ls /builds/fluidsignal/asserts/build/dist/ |\
      sed 's_fluidasserts-\|.zip__g')
echo $VER
sphinx-build -D version="v.$VER" -D release="v.$VER" \
             -a sphinx/source/ public/
sphinx-build -b linkcheck sphinx/source public/review/
