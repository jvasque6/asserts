#!usr/bin/python
import smtplib
import logging
from fluidasserts import tcp


"""
Alexander Botero - Redexel
"""

def has_vrfy(ip, port):
	
	server= smtplib.SMTP(ip, port)
	vrfy=server.verify('Admin')
	if str('250') in vrfy:
		logging.info('SMTP "VRFY" method, Details=%s, %s', ip +":"+ str(port) , 'OPEN')
	else:
		logging.info('SMTP "VRFY" method, Details=%s, %s', ip +":"+ str(port) , 'CLOSE')

	server.quit()

