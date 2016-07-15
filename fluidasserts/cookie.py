import requests
import cookie
import logging 

def __get_request(url):
	try:
		return requests.get(url)
	except ConnectionError, e:
		logging.error('Sin acceso a %s , %s', url, 'ERROR')	
		
def __post_request(url,cookie = None):
	try:
		if not cookie:
			return requests.post(url, verify=False)
		else:
			headers = {"Cookie": cookie}
			return request.post(url, verify=False, headers=headers)
	except ConnectionError, e:
		logging.error('Sin acceso a %s , %s', url, 'ERROR')	

def has_http_only(url, cookie):
	cookies = __get_request(url).headers
	print cookies
	print cookies["set-cookie"]
	if cookie in cookies:
		print "wwd"
	else:
		logging.info('%s HTTP cookie %s, Details=%s, %s', cookie, url, "Not Present", 'OPEN')
	
