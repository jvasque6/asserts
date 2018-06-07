==========
Installing
==========

``FLUIDAsserts`` is hosted on PyPI,
so you can install it easily using ``pip``
on a system with ``Python 3``: ::

   $ pip3 install -U fluidasserts

For normal/interactive usage,
you should set the environment variable ``FA_STRICT`` to false
(see below). In an ``UNIX``-like ``OS``: ::

   $ export FA_STRICT="false"

In Windows:

.. code-block:: console

   > set FA_STRICT="false"

Now you're ready to begin :doc:`testing<usage>` vulnerabilities' closure.

-----------------------------------------------
Usage in a CI (Continuous Integration) pipeline
-----------------------------------------------

You can use ``FLUIDAsserts`` in
your ``CI`` pipeline to
ensure that your software builds and ships
with no open vulnerabilities.
To achieve this, follow these steps:

#. Add the required environment variables
   ``USER``, ``PASS``, ``ORG`` and ``APP``.
   Don't worry, the values will be provided by us!:

   * ``USER``: Name of the user from our Container Registry
   * ``PASS``: The password of the user
   * ``ORG``: The name of the organization
   * ``APP``: The name of the application

   For example, in Gitlab, your environment would look like this:

   .. image:: _static/vars.png

#. Add a job to run ``FLUIDAsserts``.
   For example, in Gitlab,
   you would add these three lines to
   your ``.gitlab-ci.yml``:

   .. code-block:: yaml

      fluidasserts:
        script:
          - docker login registry.gitlab.com -u $USER -p $PASS
          - docker pull registry.gitlab.com/$ORG:$APP
          - docker run -e ORG=$ORG -e APP=$APP -e USER=$USER
                       -e PASS=$PASS -e FA_STRICT="true"
                       registry.gitlab.com/$ORG:$APP

#. Now your pipeline will break
   if any vulnerability is found to be open.
   In order to not break the build,
   but still run the tests,
   set the ``FA_STRICT`` variable above to ``"false"``.

------------
Requirements
------------

~~~~~~~~~~~~~
In a computer
~~~~~~~~~~~~~

On a modern operating system, all you need is Python 3.6.

If installing on a very barebones operating system,
make sure you have
``curl``, ``make``, ``gcc``
and the libraries
``libc``, ``libffi``, ``openssl``, and ``jpeg``.

~~~~~~~~~~~~~~~~~~~
In a CI environment
~~~~~~~~~~~~~~~~~~~

All you need is support for Docker CE 17 or higher.

~~~~~~~~
Hardware
~~~~~~~~

CPU: 4 cores @1.8GHz
RAM: 4GiB DDR3 @1.6Ghz
Disk space: 10GiB
