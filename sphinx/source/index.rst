.. FLUIDAsserts documentation master file, created by
   sphinx-quickstart on Mon Apr 30 08:31:27 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to FLUIDAsserts's documentation!
========================================

``FLUIDAsserts`` is an engine
to automate the closing of security findings
over execution environments (``DAST``).

.. image:: _static/fluidassertses.png

Setup
=====

::

   pip install -U fluidasserts
   export FA_STRICT="false"

Usage
=====

Import the required ``FLUIDAsserts`` modules into your exploit: ::

   from fluidasserts.service import http

   URL = 'http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27'

   http.has_sqli(URL)

And run your exploit: ::

   $ python ex1_open.py
   Loading modules...
   2018-02-09 11:15:22,273 - FLUIDAsserts - INFO - OPEN: http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27 Bad text present, Details=Warning.*mysql_.*

API Documentation
=================

.. toctree::
   :maxdepth: 4
   :caption: Packages:

   fluidasserts.code
   fluidasserts.format
   fluidasserts.helper
   fluidasserts.proto
   fluidasserts.system
   fluidasserts.utils
   fluidasserts
   modules

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
