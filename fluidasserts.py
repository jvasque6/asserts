#!/usr/bin/python

from util import * 
import getopt
import sys
import requests

marker = ColorMessage()
messages = Messages()


short_list = "hv"
long_list = ["script=", "--verbose"]

def main_menu(param):
	if ("-v","") in param:
		messages.app_version() , sys.exit()
	elif ("-h", '') in param:
		messages.menu() , sys.exit()
	elif not param:
		marker.fail("opcion no reconocida")
		sys.exit()
	elif ("--script") in param[0]:
		script = param[0][1]
		if script.count("/") >=2 or script.count("/") <= 0:
			marker.fail("El script debe tener el formato app/nombre o infra/nombre")
		sys.exit()
	else:
		marker.fail("opcion no reconocida")
		sys.exit()
		
def main():
	try:
		#inicio
		messages.banner()
		if not sys.argv[1:]:
			raise UserInputError("param_error")
		arg_list = getopt.getopt(sys.argv[1:],short_list,long_list)
		
		for o in arg_list:
			main_menu(o)
	except UserInputError as e:
		marker.fail(e.message)
	except getopt.GetoptError as err:
		print marker.fail(str(err))

main()


#msg = messages()
#msg.banner()




