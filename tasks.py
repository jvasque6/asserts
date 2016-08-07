from multiprocessing import Process
import shutil
from invoke import task

venv_cmd = 'pyvenv-3.4'
build_dir = 'build'

@task
def venv(context):
    print('Creating virtual environment')
    context.run('%s %s/venv' % (venv_cmd, build_dir))

@task
def deps(context):
    print('Installing dependencies')
    context.run('%s/venv/bin/pip install -r requirements.txt' % (build_dir))

@task(venv, deps)
def build(context):
    print('Builing from source')

@task
def clean_build(context):
    print('Cleaning build directory')
    if os.path.exists(build_dir):
       shutil.rmtree(build_dir)

@task
def clean_pyc(context):
    print('Cleaning compiled files (pyc)')
    import fnmatch
    for root, dirnames, filenames in os.walk('.'):
        for filename in fnmatch.filter(filenames, '*.py[cod]'):
            os.remove(os.path.join(root, filename))

@task(clean_pyc, clean_build)
def clean(context):
    print('Cleaning everything')
	
@task(build)
def install(context):
    print('Installing FLUIDAsserts in build_dir')
    shutil.copytree('fluidasserts', 'build/venv/lib/python3.4/site-packages/fluidasserts')

@task(install)
def test(context):
    print('Testing library')
    context.run('%s/venv/bin/python tests/project.py' % (build_dir))

def test():
	print "WOOO"
	
@task
def mock(context):
	from mock import httpserver
	p = Process(target=httpserver.start(), name="MockHTTPServer")
	p.start()
	#pid = os.fork()	
	#httpserv = threading.Thread(target=httpserver.start(), name="MOCK HTTP Server")
	#httpserv.setDaemon(True)
	#httpserv.start()
