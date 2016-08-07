"""Servidor HTTP basado en Flask para exponer los mock de prueba
   Consultas con:
	- geloma <glopez@fluid.la>"""
from flask import Flask
from flask import Response

app = Flask(__name__)

@app.route("/")
def home():
	return "Mock HTTP Server"
	
@app.route("/http/headers/ok/access_control_allow_origin")
def access_control_allow_origin_ok():
    resp = Response("Access-Control-Allow-Origin OK")
    resp.headers['Access-Control-Allow-Origin'] = 'https://fluid.la'
    return resp

@app.route("/http/headers/fail/access_control_allow_origin")
def access_control_allow_origin_fail():
    resp = Response("Access-Control-Allow-Origin FAIL")
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

@app.route("/http/headers/ok/cache_control")
def cache_control_ok():
    resp = Response("Cache-Control OK")
    resp.headers['Cache-Control'] = 'private, no-cache, no-store, max-age=0, no-transform'
    return resp

@app.route("/http/headers/fail/cache_control")
def cache_control_fail():
    resp = Response("Cache-Control FAIL")
    resp.headers['Cache-Control'] = 'Fail'
    return resp
    
@app.route("/http/headers/ok/content_security_policy")
def content_security_policy_ok():
    resp = Response("content-security-policy OK")
    resp.headers['content-security-policy'] = 'private, no-cache, no-store, max-age=0, no-transform'
    return resp

@app.route("/http/headers/fail/content_security_policy")
def content_security_policy_fail():
    resp = Response("Content-Security-Policy FAIL")
    resp.headers['Content-Security-Policy'] = 'Fail'
    return resp

@app.route("/http/headers/ok/content_type")
def content_type_ok():
    resp = Response("Content-Type OK")
    resp.headers['Content-Type'] = 'application/json'
    return resp

@app.route("/http/headers/fail/content_type")
def content_type_fail():
    resp = Response("Content-Type OK")
    resp.headers['Content-Type'] = 'Fail'
    return resp

@app.route("/http/headers/ok/content_type")
def expires_ok():
    resp = Response("Expires OK")
    resp.headers['Expires'] = '0'
    return resp

@app.route("/http/headers/fail/content_type")
def expires_fail():
    resp = Response("Expires OK")
    resp.headers['Expires'] = 'Fail'
    return resp
          
#TODO: Mejorar validacion multihilo
def start():
	try:
		app.run()
	except:
		print ""
		#Para evitar que se llame multiples veces el servidor cuando se hace el multi hilo, 

