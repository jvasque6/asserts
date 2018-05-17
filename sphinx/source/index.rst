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

Usage
=====

Import the required ``FLUIDAsserts`` modules into your exploit: ::

   from fluidasserts.proto import http

   http.has_sqli('http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27')

And run your exploit: ::

   $ python example.py
   ---
   # FLUIDAsserts (v. 0.20180517.2104)
   #  ___
   # | >>|> fluid
   # |___|  attacks, we hack your software
   #
   # Loading attack modules ...
   ---
   check: fluidasserts.service.http.has_multiple_text
   status: OPEN
   message: 'A bad text was present: "Warning.*mysql_.*"'
   details:
     url: http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27
   when: 2018-05-17 15:29:33.679156

API Documentation
=================

.. toctree::
   :maxdepth: 4
   :caption: Packages:

   fluidasserts.lang
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
