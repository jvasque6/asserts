#!/usr/bin/python

#FluidAssertsModules
from util import * 
from application import Application
from infraestructure import Infraestructure

#PythonModules
import getopt
import sys

marker = ColorMessage()
messages = Messages()

short_list = "hvf"
long_list = [
	"script=", "url=", "proxy=", 
	"auth=", "authUser=", "authToken=", "authPass="
]

def main_menu(param):
	if ("-v","") in param:
		messages.app_version() , sys.exit()
	elif ("-h", '') in param:
		messages.menu() , sys.exit()
	elif not param:
		raise UserError("param_error")
	elif ("--script") in param[0]:
		script = param[0][1]
		if script.count("/") >=2 or script.count("/") <= 0:
			raise UserError("script_format")
		else:
			module = script.split("/")[0]
			method = script.split("/")[1]
			if module == "app":
				app = Application(param)
				getattr(app, method)()
			elif module == "infra":
				infra = Infraestructure()
				getattr(infra, method)()
			else:
				raise UserError("module_format")
			sys.exit()
	else:
		marker.fail("opcion no reconocida")
	sys.exit()
		
def main():
	try:
		#inicio
		messages.banner()
		if not sys.argv[1:]:
			messages.menu() , sys.exit()
		arg_list = getopt.getopt(sys.argv[1:],short_list,long_list)
		for o in arg_list:
			main_menu(o)
	except UserError as e:
		marker.fail(e.message),	sys.exit()
	except getopt.GetoptError as err:
		print marker.fail(str(err)), sys.exit()
	except AttributeError as e:
		marker.fail(e.message), sys.exit()

main()



