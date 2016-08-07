#!usr/bin/python

###Mock donde se crean las simulaciones de las pruebas unitarias

""" 
Mock Smtp para crear servidor local y realizar las pruebas del protocolo smtp
Creado por Alexander Botero - Redexel
"""
def mock_smtp():
	import smtpd
	import asyncore

	server = smtpd.SMTPServer(('127.0.0.1', 25), None)

	asyncore.loop()
	
