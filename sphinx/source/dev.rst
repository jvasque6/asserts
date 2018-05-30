Developing ``Asserts``
======================

A new support module must be placed
in the appropriate package:

* :doc:`lang<fluidasserts.lang>` for code checks,
  v.g. in :doc:`Java<fluidasserts.lang.java>`
* :doc:`proto<fluidasserts.proto>` for protocols
  such as :doc:`LDAP<fluidasserts.proto.ldap>`
* :doc:`format<fluidasserts.format>` for formats
  such as :doc:`Cookies<fluidasserts.format.cookie>`
* :doc:`systfluidasserts.syst>` for global OS checks
  v.g. in :doc:`Linux<fluidasserts.syst.linux>`


New functions must be predicates i.e.
they must return
true if the vulnerability is open
or false if it is closed,
and show the appropriate message
from the main package: ::

   from fluidasserts import show_close, show_open

   def has_insecure_deserialization(java_dest: str) -> bool:
     if ...:
       show_open('Code uses insecure deserialization', details=...)
       return True
     else:
       show_close('Code uses secure deserialization', details=...)
       return False

This will sometimes lead to
apparently awkward function names,
like ``is_not_https_required``
but it makes sense considering
we are not testing
if ``https`` is _required_, but rather
whether the `vulnerability` "not requiring ``https``" `is open`.

Function names must be written in english
and conform to :pep:`8`
(in particular they must be written in ``snake_case``)
so that they can be used like this
from a project exploit: ::

   from fluidasserts.lang import javascript
   javascript.uses_eval('my-script.js') //check

Other good function name ideas: ::

   is_code_not_obfuscated
   is_disk_not_encrypted
   is_linter_bypassed
   has_blind_xee
   contains_commented_code

Notice that if the answer to any of these questions is true,
then we have an open vulnerability.

Bad function names: ::

   is_secure         # Too general
   has_antimalware   # Logic inverted
   ssh_version       # Not a verb

Comments, variables, parameter names, etc
should also be written in English
and conform to :pep:`8` conventions.

All modules are checked with the linters
`Pylint <https://www.pylint.org/>`_, \
`Pyflakes <https://www.pylint.org/>`_, \
`Flake8 <http://flake8.pycqa.org/en/latest/>`_, \
`Pycodestyle <https://pypi.org/project/pycodestyle/>`_, \
and the tools \
`dodgy <https://github.com/landscapeio/dodgy>`_, \
`mccabe <https://pypi.org/project/mccabe/>`_, and \
`pep8 <https://pypi.org/project/pep8/>`_ (via \
`Prospector <https://prospector.landscape.io/en/master/>`_, \
in highest strictness).
It is recommended to install and
use `overcommit <https://github.com/brigade/overcommit>`_
locally before committing.


Documentation
-------------

Docstrings should conform to :pep:`257`
and will be checked by ``pydocstyle`` in CI time.
Parameters and return specifications should be written in
plain `Sphinx <http://www.sphinx-doc.org/>`_
`ReStructured Text
<https://pythonhosted.org/an_example_pypi_project/sphinx.html#function-definitions>`_ style, while
parameter and return types must be specified using
Type Hints according to :pep:`484`: ::


   def is_long_line(line: str) -> bool
   """
   Determine if a ``line`` is *too* long.

   :param line: A line of code to test.
   :return: ``True`` if too long, ``False`` if **OK**.
   """

This is further enhanced by `MyPy <http://mypy-lang.org/>`_
and the :mod:`typing` module
which provides means to specify, in particular,
optional and multiple return types.
Type consistency will be checked by MyPy in CI time,
but not strictly.

References
----------

The following pages contain some ideas
to keep in mind when developing ``FLUIDAsserts``:

* http://haacked.com/archive/2007/09/21/unit-testing-security-example.aspx/
* https://www.owasp.org/index.php/OWASP_Secure_TDD_Project
* https://dadario.com.br/security-unit-tests-are-important/
* http://owasp.blogspot.com.co/2012/08/owasp-xelenium-security-unit-tests.html
* https://www.owasp.org/images/9/99/AutomatedSecurityTestingofWebApplications-StephendeVries.pdf
* https://www.owasp.org/images/6/62/OWASPAppSecEU2006_SecurityTestingthruAutomatedSWTests.ppt
* https://spring.io/blog/2014/05/07/preview-spring-security-test-method-security
* http://www.agiletestingframework.com/atf/testing/security-testing/
* http://blogs.adobe.com/security/2014/07/overview-of-behavior-driven-development.html
* http://www.hugeinc.com/ideas/perspective/continuous-security
* https://wiki.mozilla.org/Security/Projects/Minion
* http://devops.com/2015/04/06/automated-security-testing-continuous-delivery-pipeline/
* https://www.continuumsecurity.net/bdd-intro.html
* http://blog.joda.org/2004/11/testing-security-permission_5894.html
* http://www.ibm.com/developerworks/java/library/j-fuzztest/index.html
* http://howtodoinjava.com/junit/how-to-unit-test-spring-security-authentication-with-junit/
* https://blog.box.com/blog/a-baseline-approach-to-security-testing/
* http://morelia.readthedocs.io/en/latest/gherkin.html#gherkin
* https://dzone.com/articles/making-web-secure-one-unit
* https://www.linkedin.com/in/stephen-de-vries-4185a8
* http://www.slideshare.net/StephendeVries2/automating-security-tests-for-continuous-integration
* http://www.slideshare.net/StephendeVries2/continuous-security-testing-with-devops
* http://lettuce.it/tutorial/simple.html
* https://java.awsblog.com/post/TxDPKO4T5U0QIH/DevOps-Meets-Security-Security-Testing-Your-AWS-Application-Part-I-Unit-Testing
* https://github.com/OWASP/OWASP-Testing-Guide/blob/master/2-Introduction/2.5%20Security%20Tests%20Integrated%20in%20Development%20and%20Testing%20Workflows.md
* https://docs.hiptest.net/writing-scenarios-with-gherkin-syntax/
* http://www.arachni-scanner.com/screenshots/web-user-interface/
