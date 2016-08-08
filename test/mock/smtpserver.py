import smtpd
import asyncore

server = smtpd.SMTPServer(('127.0.0.1', 10025), None)
asyncore.loop()
