# -*- coding: utf-8 -*-

"""HTML check module."""

# 3rd party imports
from pyparsing import (makeHTMLTags)

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


def has_attribute(filename, tag, attr, value):
    """
    Check ``HTML`` attributes` values.

    This method checks whether the code retrieved by the selector
    (``selector``) inside the file (``filename``)
    has an attribute (``attr``) with the specific value (``value``).

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    :param tag: ``HTML`` tag to search.
    :type tag: string.
    :param attr: Attribute to search.
    :type attr: string
    :param value: Value the attribute should have.
    :type value: string
    :rtype: bool
    :returns: True if attribute set as specified, False otherwise.
    """
    handle = open(filename, 'r')
    html_doc = handle.read()
    handle.close()

    tag_s, _ = makeHTMLTags(tag)
    tag_expr = tag_s

    for expr in tag_expr.searchString(html_doc):
        if hasattr(expr, attr):
            if getattr(expr, attr).casefold() == value.casefold():
                return True

    return False


@track
def has_not_autocomplete(filename):
    """
    Check the autocomplete attribute.

    Check if tags ``form`` and ``input`` have the ``autocomplete``
    attribute set to ``off``.

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    :param selector: CSS selector to test.
    """

    attr = 'autocomplete'
    value = 'off'
    tag_i = 'input'
    tag_f = 'form'
    has_attr_i = has_attribute(filename, tag_i, attr, value)
    has_attr_f = has_attribute(filename, tag_f, attr, value)

    if (has_attr_i or has_attr_f) is False:
        result = True
        show_open('{} attribute in {}'.format(attr, filename))
    else:
        result = False
        show_close('{} attribute in {}'.format(attr, filename),
                   details=dict(value=value))
    return result


@track
def is_cacheable(filename):
    """Check if cache is posible.

    Verifies if the file has the tags::
       <META HTTP-EQUIV="Pragma" CONTENT="no-cache"> and
       <META HTTP-EQUIV="Expires" CONTENT="-1">

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    """
    tag = 'meta'

    attr = 'http-equiv'
    value = 'pragma'
    has_http_equiv = has_attribute(
        filename, tag, attr, value)

    if not has_http_equiv:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'content'
    value = 'no-cache'
    has_content = has_attribute(
        filename, tag, attr, value)

    if not has_content:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'http-equiv'
    value = 'expires'
    has_http_equiv = has_attribute(
        filename, tag, attr, value)

    if not has_http_equiv:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'content'
    value = '-1'
    has_content = has_attribute(
        filename, tag, attr, value)

    if not has_content:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    result = False
    show_close('{} attribute in {}'.format(attr, filename),
               details=dict(value=value))
    return result
