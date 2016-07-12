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

class UserInputError(Exception):
	def __init__(self,code):
		message = "Uncaugth error"
		if code == "param_error":
			message = "Debes enviar algun parametro intenta fluidasserts.py -h, --help"
		Exception.__init__(self, message) 
		
class Messages:
	def banner(self):	
		Pencil = ColorMessage()
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
	def app_version(self):
		Pencil = ColorMessage()
		Pencil.clean("FluidAsserts version 1.0")
		Pencil.clean("Release date on 2016-06-12")
		Pencil.clean("https://fluid.la")
	def menu(self):
		Pencil = ColorMessage()
		Pencil.clean("MISC:")
		Pencil.clean(" -v: Muestra la version")
		Pencil.clean(" -h: Muestra el menu de ayuda")
