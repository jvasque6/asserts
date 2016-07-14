import requests
import datetime

def log(vuln, toe , state): 
	time = str(datetime.datetime.now()).split(".")[0]
	line = " " +time + " - " + vuln + " - " + toe + " - " + state + "\n"
	with open("Prueba.txt", "a") as logfile:
		logfile.write(line)
			
def test_http_header(url,header):
	execution = requests.get(url)
	headers = [
		'access-control-allow-origin',
		'cache-control',
		'content-security-policy',
		'content-type',
		'expires',
		'pragma',
		'strict-transport-security',
		'x-content-type-options',
		'x-frame-options',
		'x-permitted-cross-domain-policies',
		'x-xss-protection',
	]
	if header == "all":
		for header in headers:
			test_http_header(header)
	else:
		if header in headers:
			if header in execution.headers:
				log("Encabezado HTTP "+header,url,"CLOSE")
			else:
				log("Encabezado HTTP "+header,url,"OPEN")
		else:
			log("Encabezado HTTP "+header,url,"ERROR")
