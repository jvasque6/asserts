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
# none


PYTHON_VER = '3.4'
VENV_CMD = 'pyvenv-3.4'
BUILD_DIR = 'build'
VENV_DIR = BUILD_DIR + '/venv'
PATH_DIR = VENV_DIR + '/bin'
DIST_DIR = 'dist'
PRINT_PRE = '**** FLUIDAsserts: '
PRINT_POS = '.'


def log(text):
    """Imprime en consola con prefijo y sufijo parametrizado."""
    print('{pre}{txt}{pos}'.format(pre=PRINT_PRE,
                                   txt=text,
                                   pos=PRINT_POS))


@task
def self(context):
    """Genera información de contexto para reporte de errores."""
    log('Data of who am I to report bugs')
    print('-----PEGAR AL FINAL DE UN REPORTE DE ERROR-----')
    log('Running $ date')
    context.run('date')
    log('Running $ lsb_release -a')
    context.run('lsb_release -a')
    log('Running $ pip show invoke')
    context.run('pip show invoke')
    log('Running $ whereis {cmd}'.format(cmd=VENV_CMD))
    context.run('whereis {cmd}'.format(cmd=VENV_CMD))
    log('Running $ git --version')
    context.run('git --version')
    log('Running $ git config -l')
    context.run('git config -l')
    log('Running $ git log -1')
    context.run('git --no-pager log -1')
    log('Running $ git status')
    context.run('git status')
    log('Running $ git remote -v')
    context.run('git remote -v')
    log('Running $ git remote show origin')
    context.run('git remote show origin', pty=True)
    print('-----FIN DE INFORMACION DE SISTEMA DONDE ESTA EL ERROR---')


@task
def upload(context):
    """Sube al repositorio central las ramas locales."""
    log('Running $ git push origin')
    context.run('git push origin', pty=True)


@task
def download(context):
    """Descarga cambios ocurridos en repositorio remoto central."""
    log('Running $ git remote -v')
    context.run('git remote -v', pty=True)
    log('Running $ git fetch -v origin')
    context.run('git fetch -v origin', pty=True)
    log('Running $ git branch')
    context.run('git branch', pty=True)
    log('Running $ git diff --stat HEAD..master')
    context.run('git diff --stat HEAD..master', pty=True)


@task
def re_commit(context):
    """Actualiza ultimo commit con otros cambios a incluir en el."""
    log('Running $ git commit --amend')
    context.run('git commit --amend', pty=True)


@task
def not_staged(context):
    """Cambios locales, pendientes por pasar a stage."""
    log('Running $ git diff')
    context.run('git diff', pty=True)


@task
def not_commited(context):
    """Cambios en stage, pendientes por pasar a commit (local)."""
    log('Running $ git diff --staged')
    context.run('git diff --staged', pty=True)


@task
def venv(context):
    """Crea un ambiente virtual de Python independiente del SO."""
    log('Creating virtual environment')
    context.run('{cmd} {dir}'.format(cmd=VENV_CMD, dir=VENV_DIR))


@task(venv)
def shell(context):
    """Ejecuta una shell nueva dentro del ambiente virtual."""
    log('Creating new child shell inside virtual environment')
    log('To exit CTRL+D or exit')
    context.run('bash \
                 --init-file {dir}/bin/activate'.format(dir=VENV_DIR),
                pty=True)
    log('Exiting virtual environment shell')


@task(venv)
def deps(context):
    """Instala dependencias requeridas en el ambiente virtual."""
    log('Installing dependencies')
    context.run('{pth}/pip install -r requirements.txt \
                                   --no-compile'.format(pth=PATH_DIR))


@task(deps)
def setup_dev(context):
    """Configura entorno de dllo: pre-commit, commit-msg, etc."""
    log('Running $ pre-commit install')
    context.run('{pth}/pre-commit install'.format(pth=PATH_DIR),
                pty=True)
    log('Running $ git config --local commit-template ...')
    context.run('git config --local commit.template \
                                     conf/commit-msg.txt',
                pty=True)
    log('Running $ git config --local credential.helper ...')
    context.run('git config --local credential.helper \
                                     \'cache --timeout 3600\'',
                pty=True)


@task(setup_dev)
def pre_commit(context):
    """Ejecuta hooks de pre-commit (linters)."""
    log('Running $ pre-commit run --all-files')
    context.run('{pth}/pre-commit run \
                                  --all-files'.format(pth=PATH_DIR),
                pty=True)


@task(venv)
def freeze(context):
    """Envoltura de pip freeze para cuidar las dependencias."""
    log('Obtaining current dependencies')
    context.run('{pth}/pip freeze'.format(pth=PATH_DIR))
    log('CUIDADO: NO REDIRIJA LA SALIDA A requirements.txt')
    log('CUIDADO: Siempre edite manualmente el archivo')


# pylint: disable=unused-argument
@task(deps)
def build(context):
    """Costruye el software con sus dependencias."""
    log('Building from source')


@task(build)
def dist(context):
    """Genera los instaladores."""
    log('Packaging')
    context.run('{pth}/python setup.py sdist \
                       --formats=zip,bztar'.format(pth=PATH_DIR))
    context.run('{pth}/python setup.py bdist \
                       --formats=zip,bztar'.format(pth=PATH_DIR))


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


# pylint: disable=unused-argument
@task(build)
def install(context):
    """Instala el proyecto en el ambiente virtual local."""
    log('Installing FLUIDAsserts in BUILD_DIR by symlink')
    currd = os.getcwd()
    destd = '{dir}/lib/python{ver}/site-packages/fluidasserts'.format(
        dir=VENV_DIR, ver=PYTHON_VER)
    if not os.path.exists(destd):
        os.symlink('%s/fluidasserts' % (currd), destd)


# TODO(ralvarez): Aun no invoca FTP pues circle.yml le falta docker
# TODO(ralvarez): Hacer task parametrizable para ejecutar solo suite
@task(install)
def test(context):
    """Ejecuta las pruebas de unidad que verifican el software."""
    log('Starting mocks')
    context.run('{dir}/test/server/skel/start.sh \
                 {dir}/test/server/ftp/conf.sh'.format(dir=os.getcwd()))
    log('Testing library')
    context.run('{pth}/py.test --verbose \
                               --cov=fluidasserts \
                               --cov-report term \
                               --cov-report html:{dir}/coverage/html \
                               --cov-report xml:{dir}/coverage/results.xml \
                               --cov-report annotate:{dir}/coverage/annotate \
                               --junitxml={dir}/test/results.xml \
                               --resultlog={dir}/test/results.txt \
                               test/test_ftp.py \
                               test/test_pdf.py \
                               test/test_http.py'.format(pth=PATH_DIR,
                                                         dir=BUILD_DIR),
                pty=True)
    log('Stopings mocks')
    context.run('{dir}/test/server/skel/stop.sh \
                 {dir}/test/server/ftp/conf.sh'.format(dir=os.getcwd()))


@task(deps)
def lint(context):
    """Realiza analisis de estilo sobre todo el software."""
    lint_dir = BUILD_DIR + '/lint'
    if not os.path.exists(lint_dir):
        os.makedirs(lint_dir)

    # linting with pydocstyle
    log('Linting with pydocstyle')
    context.run('{pth}/pydocstyle --count fluidasserts test *.py \
                            > {dir}/pydocstyle.txt 2>&1'.format(pth=PATH_DIR,
                                                                dir=lint_dir),
                warn=True, pty=True)
    context.run('cat {dir}/pydocstyle.txt'.format(dir=lint_dir))

    # linting with flake8 (config in setup.cfg - flake8 section)
    log('Linting with flake8')
    context.run('{pth}/flake8 --output-file={dir}/flake8.txt \
                              fluidasserts/ test/ *.py'.format(pth=PATH_DIR,
                                                               dir=lint_dir),
                warn=True, pty=True)
    log('Running: $ cat ../flake8.txt')
    context.run('cat {dir}/flake8.txt'.format(dir=lint_dir))

    # linting with pylint
    log('Linting with pylint')
    context.run('{pth}/pylint --rcfile=conf/pylintrc \
                              fluidasserts test *.py \
                              > {dir}/pylint.txt 2>&1'.format(pth=PATH_DIR,
                                                              dir=lint_dir),
                warn=True, pty=True)
    context.run('cat {dir}/pylint.txt'.format(dir=lint_dir))


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
