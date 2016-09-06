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
from configobj import ConfigObj
from invoke import task
from validate import Validator

# local imports
# none

# pylint: disable=C0103
cfg = ConfigObj('conf/conf.cfg', configspec='conf/conf.spec')
cfg.validate(Validator())  # exit si la validación falla


def log(text):
    """Imprime en consola con prefijo y sufijo parametrizado."""
    print('{pre}{txt}{pos}'.format(pre=cfg['develop']['print_pre'],
                                   txt=text,
                                   pos=cfg['develop']['print_pos']))


@task
def self(ctx):
    """Genera información para reporte de errores."""
    log('Data of who am I to report bugs')
    print('-----PEGAR AL FINAL DE UN REPORTE DE ERROR-----')
    log('Running $ date')
    ctx.run('date')
    log('Running $ lsb_release -a')
    ctx.run('lsb_release -a')
    log('Running $ pip show invoke')
    ctx.run('pip show invoke')
    log('Running $ whereis {c}'.format(c=cfg['develop']['venv_cmd']))
    ctx.run('whereis {c}'.format(c=cfg['develop']['venv_cmd']))
    log('Running $ git --version')
    ctx.run('git --version')
    log('Running $ git config -l')
    ctx.run('git config -l')
    log('Running $ git log -1')
    ctx.run('git --no-pager log -1')
    log('Running $ git status')
    ctx.run('git status')
    log('Running $ git remote -v')
    ctx.run('git remote -v')
    log('Running $ git remote show origin')
    ctx.run('git remote show origin', pty=True)
    print('-----FIN DE INFORMACION DE SISTEMA DONDE ESTA EL ERROR---')


@task
def upload(ctx):
    """Sube al repositorio central las ramas locales."""
    log('Running $ git push origin')
    ctx.run('git push origin', pty=True)


@task
def download(ctx):
    """Descarga cambios ocurridos en repositorio remoto central."""
    log('Running $ git remote -v')
    ctx.run('git remote -v', pty=True)
    log('Running $ git fetch -v origin')
    ctx.run('git fetch -v origin', pty=True)
    log('Running $ git branch')
    ctx.run('git branch', pty=True)
    log('Running $ git diff --stat HEAD..master')
    ctx.run('git diff --stat HEAD..master', pty=True)


@task
def re_commit(ctx):
    """Actualiza ultimo commit con otros cambios a incluir en el."""
    log('Running $ git commit --amend')
    ctx.run('git commit --amend', pty=True)


@task
def not_staged(ctx):
    """Pendiente por pasar a stage."""
    log('Running $ git diff')
    ctx.run('git diff', pty=True)


@task
def not_commited(ctx):
    """Pendiente por pasar a commit (local)."""
    log('Running $ git diff --staged')
    ctx.run('git diff --staged', pty=True)


@task
def venv(ctx):
    """Crea un ambiente virtual de Python independiente del SO."""
    log('Creating virtual environment')
    ctx.run('{c} {d}'.format(c=cfg['develop']['venv_cmd'],
                             d=cfg['develop']['venv_dir']))


@task(venv)
def shell(ctx):
    """Ejecuta una shell nueva dentro del ambiente virtual."""
    log('Creating new child shell inside virtual environment')
    log('To exit CTRL+D or exit')
    ctx.run('bash \
               --init-file {b}/activate \
            '.format(b=cfg['develop']['path_dir']), pty=True)
    log('Exiting virtual environment shell')


@task(venv)
def deps(ctx):
    """Instala dependencias requeridas en el ambiente virtual."""
    log('Installing dependencies')
    ctx.run('{b}/pip \
                   install \
                   -r requirements.txt \
                   --no-compile \
            '.format(b=cfg['develop']['path_dir']))


@task(deps)
def setup_dev(ctx):
    """Configura entorno de dllo: pre-commit, commit-msg, etc."""
    log('Running $ pre-commit install')
    ctx.run('{b}/pre-commit \
                     install \
            '.format(b=cfg['develop']['path_dir']), pty=True)
    log('Running $ git config --local commit-template ...')
    ctx.run('git config \
                   --local \
                   commit.template conf/commit-msg.txt', pty=True)
    log('Running $ git config --local credential.helper ...')
    ctx.run('git config \
                   --local \
                   credential.helper \'cache --timeout 3600\'', pty=True)


@task(setup_dev)
def pre_commit(ctx):
    """Ejecuta hooks de pre-commit (linters)."""
    log('Running $ pre-commit run --all-files')
    ctx.run('{b}/pre-commit \
                   run \
                   --all-files \
            '.format(b=cfg['develop']['path_dir']), pty=True)


@task(venv)
def freeze(ctx):
    """Envoltura de pip freeze para cuidar las dependencias."""
    log('Obtaining current dependencies')
    ctx.run('{b}/pip freeze'.format(b=cfg['develop']['path_dir']))
    log('CUIDADO: NO REDIRIJA LA SALIDA A requirements.txt')
    log('CUIDADO: Siempre edite manualmente el archivo')


# pylint: disable=unused-argument
@task(deps)
def build(ctx):
    """Costruye el software con sus dependencias."""
    log('Building from source')


@task(build)
def dist(ctx):
    """Genera los instaladores."""
    log('Packaging')
    ctx.run('{b}/python setup.py \
                          sdist \
                          --formats=zip,bztar \
            '.format(b=cfg['develop']['path_dir']))
    ctx.run('{b}/python setup.py \
                          bdist \
                          --formats=zip,bztar \
            '.format(b=cfg['develop']['path_dir']))


@task
def clean(ctx):
    """Borra todos los archivos intermedios generados."""
    log('Cleaning build directory')
    if os.path.exists(cfg['develop']['build_dir']):
        shutil.rmtree(cfg['develop']['build_dir'])

    log('Cleaning dist directory')
    if os.path.exists(cfg['develop']['dist_dir']):
        shutil.rmtree(cfg['develop']['dist_dir'])

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
    ctx.run('py3clean .')


# pylint: disable=unused-argument
@task(build)
def install(ctx):
    """Instala el proyecto en el ambiente virtual local."""
    log('Installing FLUIDAsserts in build directory by symlink')
    currd = os.getcwd()
    destd = ('{v}/lib/python{e}/site-packages/'
             'fluidasserts').format(v=cfg['develop']['venv_dir'],
                                    e=cfg['develop']['python_ver'])
    if not os.path.exists(destd):
        os.symlink('%s/fluidasserts' % (currd), destd)


# TODO(ralvarez): Aun no invoca FTP pues circle.yml le falta docker
# TODO(ralvarez): Hacer task parametrizable para ejecutar solo suite
@task(install)
def test(ctx):
    """Ejecuta las pruebas de unidad que verifican el software."""
    log('Starting mocks')
    ctx.run('{c}/test/server/skel/start.sh \
                                    {c}/test/server/ftp/conf.sh \
            '.format(c=(os.getcwd())))
    log('Testing library')
    ctx.run('{b}/py.test \
                   --verbose \
                   --cov=fluidasserts \
                   --cov-report term \
                   --cov-report html:{o}/coverage/html \
                   --cov-report xml:{o}/coverage/results.xml \
                   --cov-report annotate:{o}/coverage/annotate \
                   --junitxml={o}/test/results.xml \
                   --resultlog={o}/test/results.txt \
                   test/test_ftp.py \
                   test/test_pdf.py \
                   test/test_http.py \
            '.format(b=cfg['develop']['path_dir'],
                     o=cfg['develop']['build_dir']), pty=True)
    log('Stopings mocks')
    ctx.run('{c}/test/server/skel/stop.sh \
                                    {c}/test/server/ftp/conf.sh \
            '.format(c=os.getcwd()))


@task(deps)
def lint(ctx):
    """Realiza analisis de estilo sobre todo el software."""
    lint_dir = cfg['develop']['build_dir'] + '/lint'
    if not os.path.exists(lint_dir):
        os.makedirs(lint_dir)

    # linting with pydocstyle
    log('Linting with pydocstyle')
    ctx.run('{b}/pydocstyle \
                   --count \
                   *.py \
                   test \
                   fluidasserts \
                   1> {o}/pydocstyle.txt \
                   2>&1 \
            '.format(b=cfg['develop']['path_dir'], o=lint_dir),
            warn=True, pty=True)
    ctx.run('cat {o}/pydocstyle.txt'.format(o=lint_dir))

    # linting with flake8 (config in setup.cfg - flake8 section)
    log('Linting with flake8')
    ctx.run('{b}/flake8 \
                   --output-file={o}/flake8.txt \
                   *.py \
                   test/ \
                   fluidasserts/ \
            '.format(b=cfg['develop']['path_dir'], o=lint_dir),
            warn=True, pty=True)
    log('Running: $ cat ../flake8.txt')
    ctx.run('cat {o}/flake8.txt'.format(o=lint_dir))

    # linting with pylint
    log('Linting with pylint')
    ctx.run('{b}/pylint \
                   --rcfile=conf/pylintrc \
                   *.py \
                   test \
                   fluidasserts \
                   > {o}/pylint.txt \
                   2>&1 \
            '.format(b=cfg['develop']['path_dir'], o=lint_dir),
            warn=True, pty=True)
    ctx.run('cat {dir}/pylint.txt'.format(dir=lint_dir))


@task(deps)
def style(ctx):
    """Realiza mejoras automaticas de estilo."""
    log('Correcting style with autopep8')
    ctx.run('{b}/autopep8 \
                   -vv \
                   --recursive \
                   --in-place \
                   *.py \
                   test \
                   fluidasserts \
            '.format(b=cfg['develop']['path_dir']))


@task(deps)
def doc(ctx):
    """Genera la documentación de forma automatica."""
    log('Generating documentation')
    ctx.run('{b}/pdoc \
                   --html \
                   --html-dir {o}/doc \
                   --all-submodules \
                   --overwrite \
                   fluidasserts \
            '.format(b=cfg['develop']['path_dir'],
                     o=cfg['develop']['build_dir']))
