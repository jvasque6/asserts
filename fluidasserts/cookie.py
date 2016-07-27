import requests
import logging 
from http.cookies import BaseCookie 

def __get_request(url):
	try:
		return requests.get(url)
	except ConnectionError:
		logging.error('Sin acceso a %s , %s', url, 'ERROR')	
		
def has_http_only(url, cookie_name):
	http_req = __get_request(url)
	cookielist = BaseCookie(http_req.headers["set-cookie"])
	if cookie_name in cookielist:
		result = "OPEN"
		if cookielist[cookie_name]["httponly"]:
			result = "CLOSE"
		logging.info('%s HTTP cookie %s, Details=%s, %s', cookie_name, url, cookielist[cookie_name], result)
	else:
		logging.info('%s HTTP cookie %s, Details=%s, %s', cookie_name, url, "Not Present", 'OPEN')

def has_secure(url, cookie_name):
	http_req = __get_request(url)
	cookielist = BaseCookie(http_req.headers["set-cookie"])
	if cookie_name in cookielist:
		result = "OPEN"
		if cookielist[cookie_name]["secure"]:
			result = "CLOSE"
		logging.info('%s HTTP cookie %s, Details=%s, %s', cookie_name, url, cookielist[cookie_name], result)
	else:
		logging.info('%s HTTP cookie %s, Details=%s, %s', cookie_name, url, "Not Present", 'OPEN')
