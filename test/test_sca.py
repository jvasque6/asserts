# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.sca packages."""

# standard imports
import io
import os
import sys

# 3rd party imports
# None

# local imports
from fluidasserts.sca import bower
from fluidasserts.sca import chocolatey
from fluidasserts.sca import maven
from fluidasserts.sca import npm
from fluidasserts.sca import nuget
from fluidasserts.sca import pypi
import fluidasserts.utils.decorators
import fluidasserts

# Constants
fluidasserts.utils.decorators.UNITTEST = True

#
# Open tests
#


def test_has_vulnerabilities_open():
    """Search vulnerabilities."""
    assert bower.has_vulnerabilities('jquery')
    assert chocolatey.has_vulnerabilities('python')
    assert maven.has_vulnerabilities('maven')
    assert npm.has_vulnerabilities('npm')
    assert nuget.has_vulnerabilities('jquery')
    assert pypi.has_vulnerabilities('pip')



#
# Closing tests
#

def test_has_vulnerabilities_close():
    """Search vulnerabilities."""
    assert not bower.has_vulnerabilities('jquery', version='3.0.0')
    assert not bower.has_vulnerabilities('jqueryasudhaiusd', version='3.0.0')
    assert not chocolatey.has_vulnerabilities('python', version='3.7.0')
    assert not chocolatey.has_vulnerabilities('jqueryasudhai', version='3.7')
    assert not maven.has_vulnerabilities('maven', version='5.0.0')
    assert not maven.has_vulnerabilities('mavenasdasda', version='5.0.0')
    assert not npm.has_vulnerabilities('npm', version='10.0.0')
    assert not npm.has_vulnerabilities('npasdasdasm', version='10.0.0')
    assert not nuget.has_vulnerabilities('jquery', version='10.0.0')
    assert not nuget.has_vulnerabilities('jqueryasdasd', version='10.0.0')
    assert not pypi.has_vulnerabilities('pips')
    assert not pypi.has_vulnerabilities('pipasdiahsds')

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'
    assert not bower.has_vulnerabilities('jquery')
    assert not chocolatey.has_vulnerabilities('python')
    assert not maven.has_vulnerabilities('maven')
    assert not npm.has_vulnerabilities('npm')
    assert not nuget.has_vulnerabilities('jquery')
    assert not pypi.has_vulnerabilities('pip')
