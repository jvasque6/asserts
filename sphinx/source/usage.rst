Usage
=====

Most of ``FLUIDAsserts`` functions for the end-user
are `predicates` regarding a specific vulnerability.
In that sense,
you "ask" ``Asserts``
whether a certain `Target of Evaluation`
has an open vulnerability of some type or
if it has been closed.

``Asserts`` replies by telling you
that the status of the vulnerability is
`OPEN` or `CLOSED` plus
additional info, such as
why it thinks the flaw is or is not still there,
where it is found,
when it was tested,
and the `fingerprint` (the gory details of the transaction).

SQL Injection
-------------

To verify that
a SQL injection is still open,
you can write a script like this:

.. code-block:: python

   from fluidasserts.proto import http
   http.has_sqli('http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27')

Then run it:

.. code-block:: yaml

   $ python open_sqli.py
   ---
   # FLUIDAsserts (v. 18.5.39898)
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
      sha256: 584cb66eea5305d4f4e87f8a46cfa93f8b4da09df2c12e53552679f23260b33e
      banner: "Server: nginx/1.4.1\r\nDate: Mon, 26 Jan 1970 00:40:14 GMT\r\nContent-Type:\
        \ text/xml\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By:\
        \ PHP/5.3.10-1~lucid+2uwsgi2"
    url: http://testphp.vulnweb.com/AJAX/infoartist.php
   when: 2018-05-28 11:09:04.574114

To verify that a SQL injection is closed,
use the same function:

.. code-block:: python

   from fluidasserts.proto import http
   http.has_sqli('http://testphp.vulnweb.com/AJAX/infoartist.php?id=3')

.. code-block:: yaml

   $ python closed_sqli.py
   ---
   # FLUIDAsserts (v. 18.5.39898)
   #  ___
   # | >>|> fluid
   # |___|  attacks, we hack your software
   #
   # Loading attack modules ...
   ---
   check: fluidasserts.proto.http.has_sqli
   status: CLOSED
   message: No bad text was present
   details:
     fingerprint:
       sha256: b5e37316077f6df28ebcdf0d3f158e67ce309de21d1419cad8e0faf444bfd1cc
       banner: "Server: nginx/1.4.1\r\nDate: Mon, 26 Jan 1970 00:40:29 GMT\r\nContent-Type:\
         \ text/xml\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By:\
         \ PHP/5.3.10-1~lucid+2uwsgi2"
     url: http://testphp.vulnweb.com/AJAX/infoartist.php?id=3
   when: 2018-05-28 11:09:04.574114

Cross-Site Scripting (``XSS``)
----------------------------

The function :func:`.has_xss` requires
a few more parameters: ::

   from fluidasserts.proto import http

   URL = 'http://testphp.vulnweb.com/guestbook.php'
   BAD_TEXT = r'<script>alert\("Hacked by FLUIDAttacks"\);<\/script>'
   DATA = {
       'name': 'anonymous user',
       'submit': 'add message',
       'text': '<script>alert("Hacked by FLUIDAttacks");</script>'
   }

   http.has_xss(URL, BAD_TEXT, data=DATA)

.. code-block:: yaml

   $ python open_xss.py
   ---
   # FLUIDAsserts (v. 18.5.39898)
   #  ___
   # | >>|> fluid
   # |___|  attacks, we hack your software
   #
   # Loading attack modules ...
   ---
   check: fluidasserts.proto.http.has_xss
   status: OPEN
   message: 'Bad text present: "<script>alert\("Hacked by FLUIDAttacks"\);<\/script>"'
   details:
     fingerprint:
       sha256: 8d96d0f0ff4a64d41d1cb94b94e5169c5c4111cd2655c1aca1b18ae1d6248fee
       banner: "Server: nginx/1.4.1\r\nDate: Mon, 26 Jan 1970 04:53:36 GMT\r\nContent-Type:\
         \ text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By:\
         \ PHP/5.3.10-1~lucid+2uwsgi2\r\nContent-Encoding: gzip"
     url: http://testphp.vulnweb.com/guestbook.php
   when: 2018-05-28 15:22:11.782679

To test if
an ``XSS`` vulnerability has been closed: ::

   from fluidasserts.proto import http

   URL = 'http://testphp.vulnweb.com/guestbook.php'
   BAD_TEXT = r'<script>alert\("Hacked by FLUIDAttacks"\);<\/script>'
   DATA = {
       'name': 'anonymous user',
       'submit': 'add message',
       'text': 'Hacked by FLUIDAttacks'
   }

   http.has_xss(URL, BAD_TEXT, data=DATA)

.. code-block:: yaml

   $ python open_xss.py
   ---
   # FLUIDAsserts (v. 18.5.39898)
   #  ___
   # | >>|> fluid
   # |___|  attacks, we hack your software
   #
   # Loading attack modules ...
   ---
   check: fluidasserts.proto.http.has_xss
   status: CLOSED
   message: 'Bad text not present: "<script>alert\("Hacked by FLUIDAttacks"\);<\/script>"'
   details:
     fingerprint:
       sha256: 5c07a74903fce8bbe0f118916f9f21bbdcc4a8abeac77bb4e7604e298859b3d8
       banner: "Server: nginx/1.4.1\r\nDate: Mon, 26 Jan 1970 05:10:54 GMT\r\nContent-Type:\
         \ text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By:\
         \ PHP/5.3.10-1~lucid+2uwsgi2\r\nContent-Encoding: gzip"
     url: http://testphp.vulnweb.com/guestbook.php
   when: 2018-05-28 15:39:30.252734

