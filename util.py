from urlparse import urlparse
import random 

class ColorMessage:
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	RED = '\033[31m'
	WHITE = '\033[50m'
	PURPLE = '\033[95m'
	CYAN = '\033[96m'
	ENDC = '\033[0m'
	def success (self, msg):
		print (self.GREEN + "[+] " + msg + self.ENDC)
	def fail (self, msg):
		print (self.RED + "[*] " + msg + self.ENDC)	
	def banner (self, msg):
		print (self.BLUE + msg + self.ENDC)		
	def clean (self, msg):
		print (self.WHITE + msg + self.ENDC)

class UserError(Exception):
	def __init__(self,code):
		message = "Error desconocido"
		if code == "param_error":
			message = "Debes enviar algun parametro intenta fluidasserts.py -h, --help"
		if code == "script_format":
			message = "El script debe tener el formato app/nombre o infra/nombre"
		if code == "module_format":
			message = "Solo existen los modulos app o infra"
		if code == "auth_format":
			message = "Ese tipo de autenticacion no existe prueba con [http, digest, oauth]"
		if code == "auth_credentials":
			message = "cuando usas una autenticacion --http debes usar --authUser o --authToken y --authPass"
		Exception.__init__(self, message) 

class ArgWrapper ():				
	def getArg (self, args, index):
		arg = None
		for i in args:
			if index in i:
				arg = i[1]
		return arg
	
class Messages:
	def banner(self):
		Pencil = ColorMessage()	
		if random.randrange(1,20) % 2 == 0:
			Pencil.banner(" ______ _       _     _                            _        ")
			Pencil.banner("|  ____| |     (_)   | |   /\                     | |       ")   
			Pencil.banner("| |__  | |_   _ _  __| |  /  \   ___ ___  ___ _ __| |_ ___  ")  
			Pencil.banner("|  __| | | | | | |/ _` | / /\ \ / __/ __|/ _ \ '__| __/ __| ")   
			Pencil.banner("| |    | | |_| | | (_| |/ ____ \\__ \__ \  __/ |  | |_\__ \ ")	  
			Pencil.banner("|_|    |_|\__,_|_|\__,_/_/    \_\___/___/\___|_|   \__|___/ ")	
			Pencil.clean ("      ____                                               ")
			Pencil.clean (" _||__|  |  ______   ______   ______   FLUIDSIGNAL   	")
			Pencil.clean ("(        | |      | |      | |      |           TOOL     ") 
			Pencil.clean ("/-()---() ~ ()--() ~ ()--() ~ ()--()                V1.0 ") 	   
			Pencil.clean ("-----------------------------------------------------------")
		else:
			Pencil.banner ("  ______	 ______ _       _     _                            _        ")
			Pencil.banner (" / ____ \ 	|  ____| |     (_)   | |   /\                     | |       ")
			Pencil.banner ("/ /    \ \	| |__  | |_   _ _  __| |  /  \   ___ ___  ___ _ __| |_ ___  ")
			Pencil.banner ("| |    | |	|  __| | | | | | |/ _` | / /\ \ / __/ __|/ _ \ '__| __/ __| ")
			Pencil.banner ("\ \____/ /	| |    | | |_| | | (_| |/ ____ \__ \__ \  __/ |  | |_\__ \  ")
			Pencil.banner (" \______/ 	|_|    |_|\__,_|_|\__,_/_/    \_\___/___/\___|_|   \__|___/ ")
			Pencil.clean (" FLUID SIGNAL TOOL V1.0") 	   
			Pencil.clean ("--------------------------------------------------------------------------------")
			
	def app_version(self):
		Pencil = ColorMessage()
		Pencil.clean("FluidAsserts version 1.0")
		Pencil.clean("Release date on 2016-06-12")
		Pencil.clean("https://fluid.la")
	def menu(self):
		Pencil = ColorMessage()
		Pencil.clean("\nObjetivo:")
		Pencil.clean(" --script=modulo/funcion  Invoca el script a usar")
		Pencil.clean(" --url=URL 		  URL (http://google.com o http://10.3.2.1:81)")
		Pencil.clean("\nAutenticacion:")
		Pencil.clean(" --auth=AUTH		  Selecciona un tipo de autenticacion HTTP puede ser http,digest,oauth")
		Pencil.clean(" --authUser=USER	  Configura un usuario para la autenticacion HTTP o DIGEST")
		Pencil.clean(" --authPass=PASS   	  Configura una clave para la autenticacion HTTP,OAUTH o DIGEST")
		Pencil.clean(" --authToken=TOKEN 	  Configura el token para la autenticacion OAUTH")
		Pencil.clean("\nPeticion:")
		Pencil.clean(" --proxy=PROXY  	  Usa un proxy para conectarse con la URL objetivo")
		Pencil.clean("\nOpciones:")
		Pencil.clean(" -v			  Muestra la version")
		Pencil.clean(" -h			  Muestra el menu de ayuda")
		Pencil.clean("\nEjemplos:")
		Pencil.clean("./fluidasserts.py --script=app/headers --url=http://10.2.3.2")
		Pencil.clean("./fluidasserts.py --script=infra/brutessh")
