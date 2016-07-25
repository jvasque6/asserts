#!usr/bin/python
import smtplib
from fluidasserts import tcp


"""
Alexander Botero - Redexel
"""

def has_vrfy(ip, port):
	
	server= smtplib.SMTP(ip, port)
	vrfy=server.verify('Admin')
	if str('250') in vrfy:
		print ("The vulnerability Is Open")
	else:
		print ("The vulnerability Is Close")

	server.quit()

def is_open(ip, port = 25):
	tcp.openport(ip, port)
