``FLUIDAsserts`` is an engine
to automate the closing of security findings
over execution environments (``DAST``).

Setup
=====

.. code-block:: text

   pip install -U fluidasserts

Usage
=====

Import the required ``FLUIDAsserts`` modules into your exploit:

.. code-block:: python

   from fluidasserts.proto import http

   http.has_sqli('http://testphp.vulnweb.com/AJAX/infoartist.php?id=3%27')

And run your exploit:

.. code-block:: text

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
