import os
import shutil
from invoke import task

venv_cmd = 'pyvenv-3.4'
build_dir = 'build'
venv_dir = build_dir + '/venv'
path_dir = venv_dir + '/bin'
dist_dir = 'dist'


@task
def venv(context):
    print('Creating virtual environment')
    context.run('pyvenv-3.4 {venv}'.format(venv=venv_dir))


@task(venv)
def deps(context):
    print('Installing dependencies')
    context.run('{path}/pip install -r requirements.txt'.format(path=path_dir))


@task(deps)
def build(context):
    print('Building from source')


@task(build)
def dist(context):
    print('Packaging')
    context.run(
        '{path}/python setup.py sdist --formats=zip,bztar'.format(path=path_dir))
    context.run(
        '{path}/python setup.py bdist --formats=zip,bztar'.format(path=path_dir))


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
    destination_dir = '{venv}/lib/python3.4/site-packages/fluidasserts'.format(
        venv=venv_dir)
    if not os.path.exists(destination_dir):
        os.symlink('%s/fluidasserts' % (current_dir), destination_dir)


# TODO(ralvarez): Aun no invoca FTP pues circle.yml le falta llamar docker
# TODO(ralvarez): Hacer task parametrizable para ejecutar solo una suite
@task(install)
def test(context):
    print('Testing library')
    context.run('{path}/py.test --cov=fluidasserts \
                                --cov-report term-missing \
                                --cov-report html:{build}/coverage/html \
                                --cov-report xml:{build}/coverage/results.xml \
                                --cov-report annotate:{build}/coverage/annotate \
                                --junitxml={build}/test/results.xml \
                                --resultlog={build}/test/results.txt \
                                test/test_pdf.py \
                                test/test_http.py'.format(path=path_dir,
                                                          build=build_dir))


@task(deps)
def lint(context):
    lint_dir = build_dir + '/lint'
    if not os.path.exists(lint_dir):
        os.makedirs(lint_dir)
    print('Linting with flake8')
    context.run('{path}/flake8 --statistics \
                               --count \
                               --output-file={lint}/flake8.txt \
                               fluidasserts test'.format(path=path_dir,
                                                         lint=lint_dir),
                warn=True)
    context.run('cat {lint}/flake8.txt'.format(lint=lint_dir))
    print('Linting with pylint')
    context.run('{path}/pylint fluidasserts test > {lint}/pylint.txt'.format(path=path_dir,
                                                                             lint=lint_dir),
                warn=True)
    context.run('cat {lint}/pylint.txt'.format(lint=lint_dir))

@task(deps)
def style(context):
    print('Correcting style with autopep8')
    context.run('{path}/autopep8 -vv --recursive --in-place fluidasserts test'.format(path=path_dir))

@task(deps)
def docs(context):
    print('Generating documentation')
    context.run('{path}/pdoc --html --html-dir build/docs --all-submodules --overwrite fluidasserts'.format(path=path_dir))
