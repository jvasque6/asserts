import os
import shutil
from invoke import task

venv_cmd = 'pyvenv-3.4'
build_dir = 'build'
dist_dir = 'dist'

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
def clean_dist(context):
    print('Cleaning dist directory')
    if os.path.exists(dist_dir):
       shutil.rmtree(dist_dir)

@task
def clean_pyc(context):
    print('Cleaning compiled files (pyc)')
    import fnmatch
    for root, dirnames, filenames in os.walk('.'):
        for filename in fnmatch.filter(filenames, '*.py[cod]'):
            os.remove(os.path.join(root, filename))

@task(clean_pyc, clean_build, clean_dist)
def clean(context):
    print('Cleaning everything')
	
@task(build)
def install(context):
    print('Installing FLUIDAsserts in build_dir by symlink')
    current_dir = os.getcwd()
    destination_dir = '%s/build/venv/lib/python3.4/site-packages/fluidasserts' % (current_dir)
    if not os.path.exists(destination_dir):
        os.symlink('%s/fluidasserts' % (current_dir), destination_dir)

@task(install)
def test(context):
    print('Testing library')
    context.run('{dir}/venv/bin/py.test --cov=fluidasserts \
                                        --cov-report term-missing \
                                        --cov-report html:{dir}/coverage/html \
                                        --cov-report xml:{dir}/coverage/results.xml \
                                        --cov-report annotate:{dir}/coverage/annotate \
                                        --junitxml={dir}/test/results.xml \
                                        --resultlog={dir}/test/results.txt \
                                        test/test_pdf.py \
                                        test/test_http.py'.format(dir=build_dir))
