#!/usr/bin/python

from fluidasserts import http

http.test_http_header ("https://securityheaders.io/", "x-frame-options")
