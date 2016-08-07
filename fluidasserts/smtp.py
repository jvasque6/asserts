
#!usr/bin/python
import socket
import sys

if len(sys.argv) !=2:
	print "Use vrfy.py <username>"
	sys.exit(0)

#socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Conectar al servidor
conexion=s.connect(('190.248.14.54', 25))
#Recibimos el banner
banner=s.recv(1024)
print banner
#Comando VRFY 
s.send('VRFY ' + sys.argv[1] + '\r\n')
result=s.recv(1024)
print result
s.close()

