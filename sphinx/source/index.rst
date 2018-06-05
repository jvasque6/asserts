Welcome to FLUIDAsserts's documentation!
========================================

``FLUIDAsserts`` is an engine
to automate the closing of security findings
over execution environments.
``Asserts`` performs Dynamic and Static
Application Security Testing
(`DAST <https://www.techopedia.com/definition/30958/dynamic-application-security-testing-dast>`_ and
`SAST <https://www.owasp.org/index.php/Source_Code_Analysis_Tools>`_) and
dynamic testing of many protocols (DXST).

.. image:: _static/fluidassertses.png

``Asserts`` reuses previously handcrafted
attack vectors in order to
automate the closing of vulnerabilities.
This makes it particularly useful
since this testing can be performed by end users as-is
or as part of a continuous integration pipeline.
Thus any changes to the ``ToE``
can be tested continuously against
the closing of confirmed vulnerabilities.

Setup
=====

Simply ::

   pip3 install -U fluidasserts

Note that ``Asserts`` runs only with ``Python`` 3.

See more details in the :doc:`setup` page.

Usage
=====

Import the required ``FLUIDAsserts`` modules into your exploit: ::

   from fluidasserts.proto import http

   http.has_sqli('http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27')

And run your exploit.
``Asserts`` will tell you
whether the vulnerability
:func:`.has_sqli`
is still open
or has been closed: ::

   ---
   # FLUIDAsserts (v. 0.20180525.1529)
   #  ___
   # | >>|> fluid
   # |___|  attacks, we hack your software
   #
   # Loading attack modules ...
   ---
   check: fluidasserts.proto.http.has_sqli
   status: OPEN
   message: 'A bad text was present: "Warning.*mysql_.*"'
   details:
     fingerprint:
       sha256: 77c524976b096b4a2461979075a3c23a407055b2b76975f829c7af750c89c5fd
       banner: "Server: nginx/1.4.1\r\nDate: Fri, 23 Jan 1970 00:26:30 GMT\r\nContent-Type:\
         \ text/xml\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By:\
         \ PHP/5.3.10-1~lucid+2uwsgi2"
     url: http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27
   when: 2018-05-25 15:54:56.455875

See more use cases and examples in our :doc:`usage` page.


API Documentation
=================

.. toctree::
   :maxdepth: 4
   :caption: Packages:

   fluidasserts.lang
   fluidasserts.format
   fluidasserts.helper
   fluidasserts.proto
   fluidasserts.syst
   fluidasserts.utils
   fluidasserts
   modules

For developers
==============

See our :doc:`dev` section.


Credits
=======

See our :doc:`credits` section for information
about authorship, ownership and licensing.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
