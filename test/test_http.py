import pytest

'''Function to start and stop mock http server when is needed'''
@pytest.fixture(scope='module')
def mock(request):
    '''Starting mock HTTP server in background'''
    from test.mock import httpserver
    from multiprocessing import Process
    mock = Process(target=httpserver.start, name="MockHTTPServer")
    mock.daemon = True
    mock.start()

    '''Waiting a little bit while mock server start receiving connections'''
    import time
    time.sleep(0.1)

    '''This method kills the mock server when all the tests are finished'''
    def teardown():
        mock.terminate()
        request.addfinalizer(teardown)

from fluidasserts import http

base_url='http://localhost:5000/http/headers'

def test_access_control_allow_origin_open(mock):
    assert True == http.has_header_access_control_allow_origin('%s/access_control_allow_origin/fail' % (base_url))

def test_access_control_allow_origin_close(mock):
    assert False == http.has_header_access_control_allow_origin('%s/access_control_allow_origin/ok' % (base_url))

def test_cache_control_open(mock):
    assert True == http.has_header_cache_control('%s/cache_control/fail' % (base_url))

def test_cache_control_close(mock):
    assert False == http.has_header_cache_control('%s/cache_control/ok' % (base_url))

#
# TODO Functions in HTTP library
#
#http.has_header_x_xxs_protection('%s/access_control_allow_origin/fail' % (base_url))
#http.has_header_x_xxs_protection("http://challengeland.co/")
#http.has_header_x_frame_options("http://localhost/cursos")
#http.has_header_x_frame_options("http://challengeland.co/")
#http.has_header_x_permitted_cross_domain_policies("http://localhost/cursos")
#http.has_header_x_permitted_cross_domain_policies("http://challengeland.co/")
#http.has_header_x_content_type_options("http://localhost/cursos")
#http.has_header_x_content_type_options("http://challengeland.co")
#http.has_header_pragma("http://localhost/cursos")
#http.has_header_pragma("http://challengeland.co")
#http.has_header_expires("http://localhost/cursos")
#http.has_header_expires("http://challengeland.co")
#http.has_header_pragma("http://localhost/cursos")
#http.has_header_content_type("http://challengeland.co")
#http.has_header_content_security_policy("http://challengeland.co")
#http.has_header_content_security_policy("http://localhost/cursos")
#cookie.has_http_only("http://challengeland.co","ci_session")
#http.basic_auth("http://localhost/fluidopens/BasicAuth/","root","1234")
#http.basic_auth("http://localhost/fluidopens/BasicAuth/","Admin","1234")
# Asymetric testing
# http.response_is_stable(seconds, URL, repeat)
