# -*- coding: utf-8 -*-

"""Makefile ala Python.

Este modulo permite construir software en Python, en diferentes sistemas
operativos y mantener solo una sintaxis y lenguaje de programación para
todo el proyecto.
"""

# standard imports
import os
import shutil

# 3rd party imports
from invoke import task

# local imports


VENV_CMD = 'pyvenv-3.4'
BUILD_DIR = 'build'
VENV_DIR = BUILD_DIR + '/venv'
PATH_DIR = VENV_DIR + '/bin'
DIST_DIR = 'dist'
PRINT_PRE = '**** FLUIDAsserts: '
PRINT_POS = '.'


def log(text):
    """Permite imprimir un prefijo en todos los logs de consutruccion."""
    print('{pre}{txt}{pos}'.format(pre=PRINT_PRE,
                                   txt=text,
                                   pos=PRINT_POS))


@task
def self(context):
    """Facilita la generacion de datos de contexto cuando hay errores."""
    log('Data of who am I to report bugs')
    log('Running $ lsb_release -a')
    context.run('lsb_release -a')
    log('Running $ pip show invoke')
    context.run('pip show invoke')
    log('Running $ whereis pyvenv-3.4')
    context.run('whereis {cmd}'.format(cmd=VENV_CMD))


@task
def precommit(context):
    """Ejecuta todos los hooks de pre-commit (descarga todo lo necesario)."""
    log('Updating hooks')
    log('Running $ pre-commit run --verbose --all-files')
    context.run('{pth}/pre-commit run --all-files'.format(pth=PATH_DIR),
                pty=True)


@task
def venv(context):
    """Crea un ambiente virtual de python independiente del SO."""
    log('Creating virtual environment')
    context.run('{cmd} {dir}'.format(cmd=VENV_CMD, dir=VENV_DIR))


@task(venv)
def shell(context):
    """Crea una shell nueva dentro del ambiente virtual."""
    log('Creating new child shell inside virtual environment')
    log('To exit CTRL+D or exit')
    context.run('bash --init-file {dir}/bin/activate'.format(dir=VENV_DIR),
                pty=True)
    log('Exiting virtual environment shell')


@task(venv)
def deps(context):
    """Instala todas las dependencias requeridas en el ambiente virtual."""
    log('Installing dependencies')
    context.run('{pth}/pip install -r requirements.txt \
                                   --no-compile'.format(pth=PATH_DIR))


@task(venv)
def freeze(context):
    """Envoltura del comando pip freeze para cuidar las dependencias."""
    log('Obtaining current dependencies')
    context.run('{pth}/pip freeze'.format(pth=PATH_DIR))
    log('WARNING: DONT REDIRECT OUTPUT to requirements.txt')
    log('WARNING: Always edit manually following rules from requirements.txt')


@task(deps)
def build(context):
    """Tarea que dispara las otras tareas."""
    log('Building from source')


@task(build)
def dist(context):
    """Genera los instaladores."""
    log('Packaging')
    context.run(
        '{pth}/python setup.py sdist --formats=zip,bztar'.format(pth=PATH_DIR))
    context.run(
        '{pth}/python setup.py bdist --formats=zip,bztar'.format(pth=PATH_DIR))


@task
def clean(context):
    """Borra todos los archivos intermedios generados."""
    log('Cleaning build directory')
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)

    log('Cleaning dist directory')
    if os.path.exists(DIST_DIR):
        shutil.rmtree(DIST_DIR)

    log('Cleaning python coverage file')
    coverage_file = '.coverage'
    if os.path.exists(coverage_file):
        os.remove(coverage_file)

    log('Cleaning FLUIDAsserts log')
    fluidasserts_log = 'results.log'
    if os.path.exists(fluidasserts_log):
        os.remove(fluidasserts_log)

    log('Cleaning MANIFEST created by distutils')
    manifest_file = 'MANIFEST'
    if os.path.exists(manifest_file):
        os.remove(manifest_file)

    # Unknown dir created from time to time
    log('Cleaning .cache directory')
    cache_dir = '.cache'
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir)

    log('Cleaning Python compiled files')
    context.run('py3clean .')


@task(build)
def install(context):
    """Instala el proyecto en el ambiente virtual local."""
    log('Installing FLUIDAsserts in BUILD_DIR by symlink')
    current_dir = os.getcwd()
    destination_dir = '{dir}/lib/python3.4/site-packages/fluidasserts'.format(
        dir=VENV_DIR)
    if not os.path.exists(destination_dir):
        os.symlink('%s/fluidasserts' % (current_dir), destination_dir)


# TODO(ralvarez): Aun no invoca FTP pues circle.yml le falta llamar docker
# TODO(ralvarez): Hacer task parametrizable para ejecutar solo una suite
@task(install)
def test(context):
    """Ejecuta las pruebas de unidad que verifican el software."""
#    log('Starting mocks')
#    context.run('{dir}/test/server/ftp/start.sh'.format(dir=os.getcwd()))
    log('Testing library')
    context.run('{pth}/py.test --cov=fluidasserts \
                               --cov-report term-missing \
                               --cov-report html:{dir}/coverage/html \
                               --cov-report xml:{dir}/coverage/results.xml \
                               --cov-report annotate:{dir}/coverage/annotate \
                               --junitxml={dir}/test/results.xml \
                               --resultlog={dir}/test/results.txt \
                               test/test_pdf.py \
                               test/test_http.py'.format(pth=PATH_DIR,
                                                         dir=BUILD_DIR))
#    log('Stopings mocks')
#    context.run('{dir}/test/server/ftp/stop.sh'.format(dir=os.getcwd()))


@task(deps)
def lint(context):
    """Realiza los analisis de estilo."""
    lint_dir = BUILD_DIR + '/lint'
    if not os.path.exists(lint_dir):
        os.makedirs(lint_dir)

    # linting with flake8
    log('Linting with flake8')
    context.run('{pth}/flake8 --statistics \
                               --count \
                               --output-file={dir}/flake8.txt \
                               fluidasserts test *.py'.format(pth=PATH_DIR,
                                                              dir=lint_dir),
                warn=True)
    context.run('cat {dir}/flake8.txt'.format(dir=lint_dir))

    # linting with pylint
    log('Linting with pylint')
    context.run('{pth}/pylint fluidasserts test *.py \
                              > {dir}/pylint.txt 2>&1'.format(pth=PATH_DIR,
                                                              dir=lint_dir),
                warn=True)
    context.run('cat {dir}/pylint.txt'.format(dir=lint_dir))

    # linting with pydocstyle
    log('Linting with pydocstyle')
    context.run('{pth}/pydocstyle --count fluidasserts test *.py \
                            > {dir}/pydocstyle.txt 2>&1'.format(pth=PATH_DIR,
                                                                dir=lint_dir),
                warn=True)
    context.run('cat {dir}/pydocstyle.txt'.format(dir=lint_dir))


@task(deps)
def style(context):
    """Realiza mejoras automaticas de estilo."""
    log('Correcting style with autopep8')
    context.run('{pth}/autopep8 -vv \
                                --recursive \
                                --in-place \
                                fluidasserts test *.py'.format(pth=PATH_DIR))


@task(deps)
def doc(context):
    """Genera la documentación de forma automatica."""
    log('Generating documentation')
    context.run('{pth}/pdoc --html \
                            --html-dir build/doc \
                            --all-submodules \
                            --overwrite \
                            fluidasserts'.format(pth=PATH_DIR))
