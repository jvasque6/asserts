#!/bin/bash

if [ -z ${1+x} ]; then 
  echo "Archivo AsciiDoc no especificado"; 
  echo "Uso: '$0' DOCUMENT.adoc [BUILDDIR]"; 
  exit -1
else 
  DOCUMENT=`echo $1 | cut -d"." -f1`
  echo "El archivo AsciiDoc: $DOCUMENT.adoc"; 
fi

if [ -z ${2+x} ]; then 
  echo "Directorio de construcción no especificado"; 
  BUILDDIR="../build/docs/asciidoc"
else 
  BUILDDIR=$2
fi

# instala paquete necesario si no esta instalado
install_package() 
{
  local package="$1"	 
  dpkg -l $package | grep -q ^ii && return 1
  sudo apt-get -y install $package && return 0
}

# instala gema necesaria si no esta instalado
install_gem()
{
  local package="$1"	 
  gem query -i -n $package$ >/dev/null 2>&1 && return 1
  sudo gem install --pre $package && return 0
}

# AsciiDoc Processor Workflow
# adoc file -> asciidoc processor -> output 
asciidoc_gen()
{
  local doc="$1"; 
  local backend="$2"
  local ext="$3"
  asciidoc -o $BUILDDIR/$doc-ad-$backend.$ext -b $backend $doc.adoc
}

# AsciiDoc-DocBook Processor Workflow
# adoc file -> asciidoc processor -> docbook -> docbook processor -> output 
a2x_gen()
{
  local doc="$1"
  local backend="$2"
  local ext="$3"
  local opts="$4"
  a2x $opts -L -f $backend $doc.adoc
  mv $doc.$backend $BUILDDIR/$doc-a2x-$backend.$ext
}

# ASCIIDOCTOR-PDF PROCESSOR
# adoc file -> asciidoctor-pdf processor -> output
adrpdf_gen()
{
  local doc="$1"
  local localdir=`pwd`
  asciidoctor-pdf -a pdf-fontsdir=$localdir/fonts \
	          -a pdf-stylesdir=$localdir/styles \
                  -a pdf-style=fluid \
                  -o $BUILDDIR/$doc-adr-pdf.pdf \
                  $doc.adoc
}

# crea directorio de construccion sino esta creado
echo "Compilando en el directorio: '$BUILDDIR'"; 
mkdir -p $BUILDDIR

# Instalar paquetes requeridos y gemas 
install_package asciidoc
install_package asciidoctor
install_package lynx
install_package texlive-lang-spanish
install_gem asciidoctor-pdf

# genera documentacion con diferentes backends y en diversos formatos
asciidoc_gen $DOCUMENT html4 html
asciidoc_gen $DOCUMENT html5 html
asciidoc_gen $DOCUMENT xhtml11 html
asciidoc_gen $DOCUMENT slidy html
asciidoc_gen $DOCUMENT docbook xml
a2x_gen $DOCUMENT pdf pdf "--fop"
a2x_gen $DOCUMENT text txt "--lynx"
a2x_gen $DOCUMENT ps ps 
a2x_gen $DOCUMENT dvi dvi
adrpdf_gen $DOCUMENT

echo "Documentación generada: " $BUILDDIR
tree $BUILDDIR
