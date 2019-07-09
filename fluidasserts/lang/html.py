# -*- coding: utf-8 -*-

"""This module allows to check HTML vulnerabilities."""

# 3rd party imports
from pyparsing import (makeHTMLTags, CaselessKeyword, ParseException,
                       Literal, SkipTo, stringEnd)

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level, notify


def _has_attributes(filename: str, tag: str, attrs: dict) -> bool:
    """
    Check ``HTML`` attributes` values.

    This method checks whether the tag (``tag``) inside the code file
    (``filename``) has attributes (``attr``) with the specific values.

    :param filename: Path to the ``HTML`` source.
    :param tag: ``HTML`` tag to search.
    :param attrs: Attributes with values to search.
    :returns: True if attribute set as specified, False otherwise.
    """
    with open(filename, 'r', encoding='latin-1') as handle:
        html_doc = handle.read()

        tag_s, _ = makeHTMLTags(tag)
        tag_expr = tag_s

        result = False

        for expr in tag_expr.searchString(html_doc):
            for attr, value in attrs.items():
                try:
                    value.parseString(getattr(expr, attr))
                    result = True
                except ParseException:
                    result = False
                    break
            if result:
                break
        return result


@notify
@level('low')
@track
def has_not_autocomplete(filename: str) -> bool:
    """
    Check the autocomplete attribute.

    Check if tags ``form`` and ``input`` have the ``autocomplete``
    attribute set to ``off``.

    :param filename: Path to the ``HTML`` source.
    :returns: True if tags ``form`` and ``input`` have attribute
              ``autocomplete`` set as specified, False otherwise.
    """
    tk_off = CaselessKeyword('off')
    attr = {'autocomplete': tk_off}
    tag_i = 'input'
    tag_f = 'form'
    try:
        has_input = _has_attributes(filename, tag_i, attr)
        has_form = _has_attributes(filename, tag_f, attr)
    except FileNotFoundError as exc:
        show_unknown('There was an error',
                     details=dict(error=str(exc)))
        return False

    if not (has_input or has_form):
        result = True
        show_open('Attribute in {}'.format(filename),
                  details=dict(atributes=str(attr)))
    else:
        result = False
        show_close('Attribute in {}'.format(filename),
                   details=dict(atributes=str(attr)))
    return result


@notify
@level('low')
@track
def is_cacheable(filename: str) -> bool:
    """Check if cache is posible.

    Verifies if the file has the tags::
       <META HTTP-EQUIV="Pragma" CONTENT="no-cache"> and
       <META HTTP-EQUIV="Expires" CONTENT="-1">

    :param filename: Path to the ``HTML`` source.
    :returns: True if tag ``meta`` have attributes ``http-equiv``
              and ``content`` set as specified, False otherwise.
    """
    tag = 'meta'
    tk_pragma = CaselessKeyword('pragma')
    tk_nocache = CaselessKeyword('no-cache')
    pragma_attrs = {'http-equiv': tk_pragma,
                    'content': tk_nocache}

    tk_expires = CaselessKeyword('expires')
    tk_minusone = CaselessKeyword('-1')
    expires_attrs = {'http-equiv': tk_expires,
                     'content': tk_minusone}
    try:
        has_pragma = _has_attributes(filename, tag, pragma_attrs)
        has_expires = _has_attributes(filename, tag, expires_attrs)
    except FileNotFoundError as exc:
        show_unknown('There was an error',
                     details=dict(error=str(exc)))
        return False

    if not has_pragma or not has_expires:
        result = True
        show_open('Attributes in {}'.format(filename),
                  details=dict(pragma_attrs=str(pragma_attrs),
                               expires_attrs=str(expires_attrs)))
    else:
        result = False
        show_close('Attributes in {}'.format(filename),
                   details=dict(pragma_attrs=str(pragma_attrs),
                                expires_attrs=str(expires_attrs)))
    return result


@notify
@level('low')
@track
def is_header_content_type_missing(filename: str) -> bool:
    """Check if Content-Type header is missing.

    Verifies if the file has the tags::
       <META HTTP-EQUIV="Content-Type" CONTENT="no-cache">

    :param filename: Path to the ``HTML`` source.
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
    try:
        has_content_type = _has_attributes(filename, tag, attrs)
    except FileNotFoundError as exc:
        show_unknown('There was an error',
                     details=dict(error=str(exc)))
        return False

    if not has_content_type:
        result = True
        show_open('Attributes in {}'.format(filename),
                  details=dict(attributes=str(attrs)))
    else:
        result = False
        show_close('Attributes in {}'.format(filename),
                   details=dict(attributes=str(attrs)))
    return result
