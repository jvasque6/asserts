#! /usr/bin/env nix-shell
#! nix-shell -i bash -p docker git gitlab-runner

FA_LICENSE_KEY="set"
FA_USER_EMAIL="set"
PYPI_USER="set"
PYPI_PASS="set"
DOCKER_PASS="set"
DOCKER_USER="set"

gitlab-ci-multi-runner exec docker --docker-privileged --docker-volumes /var/run/docker.sock:/var/run/docker.sock --env "DOCKER_USER=$DOCKER_USER" --env "DOCKER_PASS=$DOCKER_PASS" --env "PYPI_USER=$PYPI_USER" --env "PYPI_PASS=$PYPI_PASS" --env "FA_LICENSE_KEY=$FA_LICENSE_KEY" --env "FA_USER_EMAIL=$FA_USER_EMAIL" build
gitlab-ci-multi-runner exec docker --docker-privileged --docker-volumes /var/run/docker.sock:/var/run/docker.sock --env "DOCKER_USER=$DOCKER_USER" --env "DOCKER_PASS=$DOCKER_PASS" --env "PYPI_USER=$PYPI_USER" --env "PYPI_PASS=$PYPI_PASS" --env "FA_LICENSE_KEY=$FA_LICENSE_KEY" --env "FA_USER_EMAIL=$FA_USER_EMAIL" test
