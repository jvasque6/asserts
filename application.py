from urlparse import urlparse
from util import ArgWrapper
from util import UserError
import requests
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
from requests_oauthlib import OAuth1 #pip install requests-oauthlib

class Application:
		
	def __init__(self, arguments):
		print arguments	
		#Inicializacion de explicita de variables
		self.auth = None
		self.authUser = None
		self.authToken = None
		self.authPass = None
		
		self.host = None
		self.host_scheme = None
		self.host_port = None
		self.path = None
		
		self.proxy = None
		wrapper = ArgWrapper()
		
		#Captura de parametros 
		host = wrapper.getArg(arguments, "--host")
		proxy = wrapper.getArg(arguments, "--proxy")
		authType = wrapper.getArg(arguments, "--auth")
		authUser = wrapper.getArg(arguments, "--authUser")
		authToken = wrapper.getArg(arguments, "--authToken")
		authPass = wrapper.getArg(arguments, "--authPass")
		
		#Validacion sobre AUTENTICACION HTTP
		if authType != None:
			if authType == "http":
				if not authUser or not authPass:
					raise UserError("auth_credentials") 
				self.auth = HTTPBasicAuth(authUser, authPass)
			elif authType == "digest":
				if not authUser or not authPass:
					raise UserError("auth_credentials")
				self.auth = HTTPDigestAuth(authUser, authPass)
			elif authType == "oauth":
				if not authToken or not authPass:
					raise UserError("auth_credentials")
				self.auth = OAuth1(authToken, authPass)
			else:
				raise UserError("auth_format")
				
		#Validacion sobre HOST
		if host != None:
			host = urlparse(host)
			self.host = host.hostname
			self.host_scheme = host.scheme
			self.host_port = host.port
			self.path = host.path
			
		#Validacion sobre proxy
		if proxy != None:
			self.proxy = {
			  'http': proxy, 'https': proxy,
			}
		
	def headers(self):
		print "x"
		
	def alex (self):
		print "alex"
