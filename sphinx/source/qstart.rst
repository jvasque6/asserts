===========
Quick Start
===========

-------
Install
-------

Simply

.. code-block:: shell-session

   $ pip3 install -U fluidasserts

Note that ``Asserts`` runs only with ``Python`` 3.

See more details in the :doc:`install` page.

-----
Usage
-----

Import the required ``FLUIDAsserts`` modules into your exploit:

.. literalinclude:: example/qstart-sqli-open.py

And run your exploit.
``Asserts`` will tell you
whether the vulnerability
:func:`.has_sqli`
is still open
or has been closed:

.. literalinclude:: example/qstart-sqli-open.py.out
   :language: yaml

See more use cases and examples in our :doc:`usage` page.
