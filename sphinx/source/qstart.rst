===========
Quick Start
===========

Simply

.. code-block:: shell-session

   $ pip3 install -U fluidasserts

Note that ``Asserts`` runs only with ``Python`` 3.

See more details in the :doc:`install` page.

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