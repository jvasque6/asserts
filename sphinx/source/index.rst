.. toctree::
   :hidden:
   :maxdepth: 1
   :caption: Navigation

   Home <self>
   setup
   usage
   ref
   dev
   credits

========================================
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

========
Features
========

Here are some of the things ``Asserts`` can do for you:

* Determine the closed or open status of a known vulnerability.
* Perform routine, generic security tests, specially in combination with...
* **Continuous Integration**: ``Asserts`` fits into your ``CI`` pipeline
  to ensure your product is released with no open vulnerabilities.
* Helps ethical hackers in their daily activities by
  automating tasks.
* Now easier to install than ever and thoroughly documented.

What kind of vulnerabilities can ``Asserts`` test?

* :mod:`Operating System <fluidasserts.syst>` vulnerabilities:
  :mod:`Linux <.linux>` and :mod:`Windows Server <.win>`.
* :mod:`Code vulnerabilities <.lang>`:
  nine languages supported
  including proprietary (:mod:`C# <.csharp>`),
  open source (:mod:`Python <.python>`),
  legacy (:mod:`RPG <.rpgle>`),
  and even the :mod:`Dockerfile <.docker>` syntax!
* :mod:`Formats <.format>`:
  ``Asserts`` test formats ranging
  from regular :mod:`text <.string>`
  to :mod:`CAPTCHAs <.captcha>`
  and :mod:`Cookies <.cookie>`.
* :mod:`Protocols <fluidasserts.proto>`:
  The heart of ``Asserts``,
  since most vulnerabilities are network-borne.
  The main network protocols like
  :mod:`SSL <.ssl>` (think `Heartbleed <http://heartbleed.com/>`_) ,
  :mod:`HTTP <.http>` (`Cross-site scripting <https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)>`_),
  :mod:`TCP <.tcp>` (open ports),
  and seven others.

As of June 5, 2018,
``Asserts`` provides 142 checks
in the scenarios above.
Use the search box in the sidebar,
peruse the :ref:`genindex`
for a bird's eye view of all the checks,
or just dive into the :doc:`ref`.

=====
Setup
=====

Simply

.. code-block:: shell-session

   $ pip3 install -U fluidasserts

Note that ``Asserts`` runs only with ``Python`` 3.

See more details in the :doc:`setup` page.

=====
Usage
=====

Import the required ``FLUIDAsserts`` modules into your exploit:

.. code-block:: python

   from fluidasserts.proto import http

   http.has_sqli('http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27')

And run your exploit.
``Asserts`` will tell you
whether the vulnerability
:func:`.has_sqli`
is still open
or has been closed:

.. code-block:: yaml

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


=================
API Documentation
=================

See our :doc:`ref` page
for the API-level documentation.

.. toctree::
   :hidden:
   :maxdepth: 4
   :caption: Packages:
   :name: api-toc

   fluidasserts.lang
   fluidasserts.format
   fluidasserts.helper
   fluidasserts.proto
   fluidasserts.syst
   fluidasserts.utils
   fluidasserts

==============
For developers
==============

See our :doc:`dev` section.


=======
Credits
=======

See our :doc:`credits` section for information
about authorship, ownership and licensing.


==================
Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
