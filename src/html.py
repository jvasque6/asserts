# -*- coding: utf-8 -*-

"""

Modulo para verificacion de vulnerabilides en codigo HTML.
Este modulo permite verificar vulnerabilidades propias de HTML como:
    * Formularios que no tengan el atributo autocomplete en off.

Autor: Juan Escobar
Email: jescobar@fluid.la

"""

import logging
# standard imports
import re

# 3rd party imports
from bs4 import BeautifulSoup


def __has_attribute(filename, selector, tag, attr, value):
    """
        Este metodo verifica si el codigo HTML obtenido por el selector
        (selector) dentro del archivo (filename) tiene algun atributo (attr)
        con un valor (value) especifico.

        <filename> debe ser una ruta local, por ejemplo: /data/vulnerable.html
        <selector> puede ser obtenido desde la consola de Google Chrome:
            1. Abrir la consola de Google Chrome
            2. Ir a la pestana Elements
            3. Clic derecho sobre la etiqueta HTML que se quiera copiar y
               seleccionar la opcion Copy > Copy Selector
        <attr> es el atributo a buscar, por ejemplo: autocomplete
        <tag> debe ser el nombre de la etiqueta HTML donde se aplicara la
              expresion regular, puede ser una o mas etiquetas, por ejemplo:
              "a", "[form|input]", "table", etc.
        <value> es el valor que se espera tenga el atributo, por ejemplo con
                autocomplete: on, off.

    """

    handle = open(filename, 'r')
    html_doc = handle.read()
    handle.close()

    soup = BeautifulSoup(html_doc, 'html.parser')
    form = soup.select(selector)

    cache_rgx = r'<%s.+%s\s*=\s*["%s"|\'%s\'].*>' % (
        tag, attr, value, value)
    prog = re.compile('%s' % cache_rgx, flags=re.IGNORECASE)
    match = prog.search(str(form))

    if match is not None:
        result = True
    else:
        result = False

    return result


def has_not_autocomplete(filename, selector):
    """
        Verifica si el selector (selector) en el archivo (filename) tiene
        configurado el atributo autocomplete con valor off.

        <filename> debe ser una ruta local, por ejemplo: /data/vulnerable.html
        <selector> puede ser obtenido desde la consola de Google Chrome:
            1. Abrir la consola de Google Chrome
            2. Ir a la pestana Elements
            3. Clic derecho sobre la etiqueta HTML que se quiera copiar y
               seleccionar la opcion Copy > Copy Selector
    """

    attr = 'autocomplete'
    value = 'off'
    has_attr = __has_attribute(
        filename, selector, '[form|input]', attr, value)

    if has_attr is False:
        status = 'OPEN'
        result = True
        logging.info('%s attribute in %s, Details=%s, %s',
                     attr, filename, '', status)
    else:
        status = 'CLOSE'
        result = False
        logging.info('%s attribute in %s, Details=%s, %s',
                     attr, filename, value, status)

    return result

def has_not_pragma_nocache(filename):
    """ 
        Verifica si el archivo (filename) tiene configurada la etiqueta
        <META HTTP-EQUIV="Pragma" CONTENT="no-cache"> y 
        <META HTTP-EQUIV="Expires" CONTENT="-1">, la cual evita que se
        almacene la pagina en memoria cache.
        
        <filename> debe ser una ruta local, por ejemplo: /data/vulnerable.html
    """
    
    selector = 'html'
    tag = 'meta'
    
    """ Validacion de la primera etiqueta 
    <META HTTP-EQUIV="Pragma" CONTENT="no-cache"> """
    attr = 'http-equiv'
    value = 'pragma'
    has_http_equiv = __has_attribute(
        filename, selector, tag, attr, value)
    
    if has_http_equiv == False:
        """ Si no se tiene el atributo http-equiv="pragma" se califica como
        vulnerable y sale del metodo. """
        status = 'OPEN'
        result = True
        logging.info('%s attribute in %s, Details=%s, %s', 
            attr, filename, value, status)
        
        return result
        
    attr = 'content'
    value = 'no\-cache'
    has_content = __has_attribute(
        filename, selector, tag, attr, value)
    
    if has_content == False:
        """ Si no se tiene el atributo content="no-cache" se califica como
        vulnerable y sale del metodo. """
        status = 'OPEN'
        result = True
        logging.info('%s attribute in %s, Details=%s, %s', 
            attr, filename, value, status)
        
        return result
        
    """ Validacion de la segunda etiqueta 
    <META HTTP-EQUIV="Expires" CONTENT="-1"> """
    attr = 'http-equiv'
    value = 'expires'
    has_http_equiv = __has_attribute(
        filename, selector, tag, attr, value)
        
    if has_http_equiv == False:
        """ Si no se tiene el atributo http-equiv="expires" se califica como
        vulnerable y sale del metodo. """
        status = 'OPEN'
        result = True
        logging.info('%s attribute in %s, Details=%s, %s', 
            attr, filename, value, status)
        
        return result
    
    attr = 'content'
    value = '-1'
    has_content = __has_attribute(
        filename, selector, tag, attr, value)
        
    if has_content == False:
        """ Si no se tiene el atributo content="-1" se califica como
        vulnerable y sale del metodo. """
        status = 'OPEN'
        result = True
        logging.info('%s attribute in %s, Details=%s, %s', 
            attr, filename, value, status)
        
        return result
        
    status = 'CLOSE'
    result = False
    logging.info('%s attribute in %s, Details=%s, %s', 
            attr, filename, value, status)
    
    return result