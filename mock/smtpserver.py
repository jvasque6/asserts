import smtpd
import asyncore

def vulnerable():
	server = smtpd.SMTPServer(('127.0.0.1', 25), None)
	asyncore.loop()

vulnerable()
