# -*- coding: utf-8 -*-

"""HTML check module."""

# 3rd party imports
from pyparsing import (makeHTMLTags, CaselessKeyword, ParseException,
                       Literal, SkipTo, stringEnd)

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


def has_attributes(filename, tag, attrs):
    """
    Check ``HTML`` attributes` values.

    This method checks whether the code retrieved by the selector
    (``selector``) inside the file (``filename``)
    has an attribute (``attr``) with the specific value (``value``).

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    :param tag: ``HTML`` tag to search.
    :type tag: string.
    :param attr: Attributes with values to search.
    :type attr: dictionary
    :rtype: bool
    :returns: True if attribute set as specified, False otherwise.
    """
    handle = open(filename, 'r')
    html_doc = handle.read()
    handle.close()

    tag_s, _ = makeHTMLTags(tag)
    tag_expr = tag_s

    result = False

    for expr in tag_expr.searchString(html_doc):
        for attr, value in attrs.items():
            try:
                value.parseString(getattr(expr, attr))
                result = True
            except ParseException:
                continue
    return result


@track
def has_not_autocomplete(filename):
    """
    Check the autocomplete attribute.

    Check if tags ``form`` and ``input`` have the ``autocomplete``
    attribute set to ``off``.

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    :rtype: bool
    :returns: True if tags ``form`` and ``input`` have attribute
              ``autocomplete`` set as specified, False otherwise.
    """
    tk_off = CaselessKeyword('off')
    attr = {'autocomplete': tk_off}
    tag_i = 'input'
    tag_f = 'form'
    has_attr_i = has_attributes(filename, tag_i, attr)
    has_attr_f = has_attributes(filename, tag_f, attr)

    if (has_attr_i or has_attr_f) is False:
        result = True
        show_open('Attribute in {}'.format(filename),
                  details=dict(atributes=attr))
    else:
        result = False
        show_close('Attribute in {}'.format(filename),
                   details=dict(atributes=attr))
    return result


@track
def is_cacheable(filename):
    """Check if cache is posible.

    Verifies if the file has the tags::
       <META HTTP-EQUIV="Pragma" CONTENT="no-cache"> and
       <META HTTP-EQUIV="Expires" CONTENT="-1">

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    :rtype: bool
    :returns: True if tag ``meta`` have attributes ``http-equiv``
              and ``content`` set as specified, False otherwise.
    """
    tag = 'meta'
    tk_pragma = CaselessKeyword('pragma')
    tk_nocache = CaselessKeyword('no-cache')
    attrs = {'http-equiv': tk_pragma,
             'content': tk_nocache}
    has_http_equiv = has_attributes(filename, tag, attrs)

    if not has_http_equiv:
        result = True
        show_open('Attributes in {}'.format(filename),
                  details=dict(attributes=attrs))
        return result

    tk_expires = CaselessKeyword('expires')
    tk_minusone = CaselessKeyword('-1')
    attrs = {'http-equiv': tk_expires,
             'content': tk_minusone}
    has_http_equiv = has_attributes(filename, tag, attrs)

    if not has_http_equiv:
        result = True
        show_open('Attributes in {}'.format(filename),
                  details=dict(attributes=attrs))
        return result

    result = False
    show_close('Attributes in {}'.format(filename),
               details=dict(attributes=attrs))
    return result


@track
def is_header_content_type_missing(filename):
    """Check if Content-Type header is missing.

    Verifies if the file has the tags::
       <META HTTP-EQUIV="Content-Type" CONTENT="no-cache">

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    :rtype: bool
    :returns: True if tag ``meta`` have attributes ``http-equiv``
              and ``content`` set as specified, False otherwise.
    """
    tag = 'meta'
    tk_content = CaselessKeyword('content')
    tk_type = CaselessKeyword('type')
    prs_cont_typ = tk_content + Literal('-') + tk_type

    tk_type = SkipTo(Literal('/'), include=True)
    tk_subtype = SkipTo(Literal(';'), include=True)
    prs_mime = tk_type + tk_subtype

    tk_charset = CaselessKeyword('charset')
    tk_charset_value = SkipTo(stringEnd)
    prs_charset = tk_charset + Literal('=') + tk_charset_value

    prs_content_val = prs_mime + prs_charset

    attrs = {'http-equiv': prs_cont_typ,
             'content': prs_content_val}
    has_http_equiv = has_attributes(filename, tag, attrs)

    if not has_http_equiv:
        result = True
        show_open('Attributes in {}'.format(filename),
                  details=dict(attributes=attrs))
        return result

    result = False
    show_close('Attributes in {}'.format(filename),
               details=dict(attributes=attrs))
    return result
