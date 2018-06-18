==========
Installing
==========

``Fluid Asserts`` is hosted on `PyPI <https://pypi.org/project/fluidasserts/>`_,
so you can install it easily using ``pip3``
on a system with ``Python 3``: ::

   $ pip3 install -U fluidasserts

For normal/interactive usage,
you should set the environment variable ``FA_STRICT`` to false
(see below). In an ``UNIX``-like ``OS``: ::

   $ export FA_STRICT="false"

In Windows:

.. code-block:: none

   > set FA_STRICT="false"

Now you're ready to begin :doc:`testing<usage>` vulnerabilities' closure.

-------------------------
Inside a Docker container
-------------------------

If you have ``Docker`` you can check out and run ``Asserts``
inside a container. Just ::

   $ docker pull fluidattacks/asserts

And then go inside the container: ::

   $ docker run -it fluidattacks/asserts sh
   / # python3 -c "import fluidasserts"

.. literalinclude:: example/banner-only.py.out

Make sure to do the ``docker pull`` before every ``docker run``
to ensure you are running the latest ``Asserts`` version.

From inside the container you could run ``Asserts``
from the python interactive shell,
or quickly whip up a script using ``vi``.
But it would be much more useful to `mount`
the directory where your exploits live into the container: ::

  $ docker run -v /home/me/myexploits/:/exploits/ -it fluidattacks/asserts sh
  / # python3 /exploits/open-sqli.py

.. literalinclude:: example/qstart-sqli-open.py.out
   :language: yaml

-----------------------------------------------
Usage in a CI (Continuous Integration) pipeline
-----------------------------------------------

If you have an application subscribed to our
Continuous Hacking Service
which includes the use of ``Asserts``,
you can integrate it into
your ``CI`` pipeline to
ensure that your software builds and ships
with no open vulnerabilities.
We will provide a custom ``Docker`` container
with the specific tests you need
and maintain the build-breaking exploit.

To achieve this, follow these steps:

#. Add the required environment variables
   ``USER``, ``PASS``, ``ORG`` and ``APP``.
   Don't worry, the values will be provided by us!:

   * ``USER``: Name of the user from our Container Registry
   * ``PASS``: The password of the user
   * ``ORG``: The name of the organization
   * ``APP``: The name of the application

   For example, in Gitlab, your environment would look like this:

   .. figure:: _static/vars.png
      :alt: Gitlab environment variables for using Asserts

      Gitlab CI environment variables

#. Add a job to run ``Fluid Asserts``.
   For example, in Gitlab,
   you would add these three lines to
   your ``.gitlab-ci.yml``:

   .. code-block:: yaml

      fluidasserts:
        script:
          - docker login fluid-docker.jfrog.io -u "$USER" -p "$PASS"
          - docker pull fluid-docker.jfrog.io/"$ORG":"$APP"
          - docker run -e ORG="$ORG" -e APP="$APP" -e USER="$USER"
                       -e PASS="$PASS" -e FA_STRICT="true" --rm
                       fluid-docker.jfrog.io/"$ORG":"$APP"
          - docker logout fluid-docker.jfrog.io

#. Now your pipeline will break
   if any vulnerability is found to be open.
   In order to not break the build,
   but still run the tests,
   set the ``FA_STRICT`` variable above to ``"false"``.

~~~~~~~~~
CI stages
~~~~~~~~~

OK, I'm in. But in what stage should I test my app with ``Asserts``?
There are at least three good moments to perform closure testing:

* after deploying to a staging or ephemeral environment
* after deploying to the production environment
* even after every single commit!

_______________
Post-production
_______________

Just as before, we log in to the artifacts repository,
pull the custom image and run it with ``Docker``.
This time, however, we mount the volume corresponding to the current commit
(``/tmp${CI_PROJECT_DIR}/${CI_COMMIT_REF_NAME}``)
to the ``/code`` directory in the container,
since the container is already set-up to test the code there.
This job is ran only in the ``master`` branch and
in one of the latest stages, namely ``post-deploy``.

.. code-block:: yaml

   asserts-prod:
     stage: post-deploy
     script:
       - docker login fluid-docker.jfrog.io -u "$USER" -p "$PASS"
       - docker pull fluid-docker.jfrog.io/"$ORG":"$APP"
       - docker run -e ORG="$ORG" -e APP="$APP" -e USER="$USER" -e PASS="$PASS"
                    -e FA_STRICT="true" --rm -e STAGE=post-deploy
                    -v /tmp${CI_PROJECT_DIR}/${CI_COMMIT_REF_NAME}:/code
                    fluid-docker.jfrog.io/"$ORG":"$APP"
       - docker logout fluid-docker.jfrog.io
     retry: 2
     only:
       - master

_______________
Post-ephemeral
_______________

But wait! We could catch bugs before deploying to production.
If you use `ephemeral environments
<https://en.wikipedia.org/wiki/Deployment_environment#Staging>`_,
you can also perform closure testing in those:

.. code-block:: yaml

   Asserts-Review:
     stage: test
     script:
       - docker login fluid-docker.jfrog.io -u "$USER" -p "$PASS"
       - docker pull fluid-docker.jfrog.io/"$ORG":"$APP"
       - docker run -e ORG="$ORG" -e APP="$APP" -e USER="$USER" -e PASS="$PASS"
                    -e FA_STRICT="true" --rm -e STAGE=test
                    -e BRANCH="$CI_COMMIT_REF_SLUG"
                    -v /tmp${CI_PROJECT_DIR}/${CI_COMMIT_SHA}:/code
                    fluid-docker.jfrog.io/"$ORG":"$APP"
       - docker logout fluid-docker.jfrog.io
     retry: 2
     except:
       - master
       - triggers

In contrast to the post-deploy job above,
this one runs on the development branches,
during the ``test`` stage.
Otherwise, everything else is the same,
just like staging environments mirror production environments.

__________
Pre-commit
__________

As a developer you might be thinking
"why wait until all other CI stages are finished
if I just want to test whether my last commit
fixed the security hole?"
You `could` just run ``Asserts`` in your development machine,
but sometimes tiny details (like dependencies versions)
might cause the testing to pass in your machine
but fail continuous integration.

In that case you might run
the ``Dockerized`` incarnation of ``Asserts``
as a ``pre-commit`` hook:

.. code-block:: yaml

   - id: asserts-docker
     name: Running Asserts on the code
     description: Run Asserts to perform SAST
     entry: -v /path/to/your/code/:/code fluidattacks/asserts:latest /code/asserts.sh
     language: docker_image

This particular configuration is for the ``pre-commit`` tool,
but can be adapted for similar tools like ``overcommit``.
The use of such tools is convenient for the developer,
as tests can be quickly run in their machine with every commit:

   .. figure:: _static/pre-commit-ok.png
      :alt: Pre-commit pass

      Pre-commit test passed

   .. figure:: _static/pre-commit-fail.png
      :alt: Pre-commit fail

      Pre-commit test fails. Commiting is not allowed!

The same tests can also be run in CI time
(for example, in a ``lint`` stage)
to ensure that nothing is broken,
even if the developer forgot to run it.
Just

.. code-block:: none

  - pre-commit run --all-files

somewhere in your ``CI`` script.






