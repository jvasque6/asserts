#!usr/bin/python
import socket
import sys
from fluidasserts import tcp

"""
Alexander Botero - Redexel
"""
def has_vrfy(ip, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	conexion=s.connect((ip, port))
	print (s.recv(1024))
	s.send(bytes("VRFY Admin \r\n","UTF-8"))
	if str(s.recv(1024)).find("250")> -1:
		print ("Is open")
	else:
		print ("Is Close")
	s.close()
	
	
def is_open(ip, port = 25):
	tcp.openport(ip, port)

