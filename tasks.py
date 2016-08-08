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
    print('Building from source')

@task(build)
def dist(context):
    print('Packaging')
    context.run('%s/venv/bin/python setup.py sdist --formats=zip,bztar' % (build_dir))
    context.run('%s/venv/bin/python setup.py bdist --formats=zip,bztar' % (build_dir))

@task
def clean(context):
    print('Cleaning build directory')
    if os.path.exists(build_dir):
       shutil.rmtree(build_dir)

    print('Cleaning dist directory')
    if os.path.exists(dist_dir):
       shutil.rmtree(dist_dir)

    print('Cleaning python coverage file')
    coverage_file = '.coverage' 
    if os.path.exists(coverage_file):
        os.remove(coverage_file)

    print('Cleaning FLUIDAsserts log')
    fluidasserts_log = 'results.log' 
    if os.path.exists(fluidasserts_log):
        os.remove(fluidasserts_log)

    print('Cleaning MANIFEST created by distutils')
    manifest_file = 'MANIFEST' 
    if os.path.exists(manifest_file):
        os.remove(manifest_file)

    # Unknown dir created from time to time
    print('Cleaning .cache directory')
    cache_dir = '.cache'
    if os.path.exists(cache_dir):
       shutil.rmtree(cache_dir)

    print('Cleaning Python compiled files')
    context.run('py3clean .')
	
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
