import logging
import socket


def openport(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ip, port))
    status = "CLOSE"
    if result == 0:
        status = "OPEN"
    logging.info('Checking port, Details=%s, %s', ip + ":" + str(port), status)
    sock.close()


def getbanner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        result = sock.connect_ex((ip, port))
        logging.info('Banner %s, Details=%s, %s', ip + ":" +
                     str(port), sock.recv(2048), "OPEN")
    except ConnectionRefusedError:
        logging.info('Checking port, Details=%s, %s',
                     ip + ":" + str(port), "CLOSE")
    finally:
        sock.close()
