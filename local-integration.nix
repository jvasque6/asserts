#! /usr/bin/env nix-shell
#! nix-shell -i bash -p docker git gitlab-runner

FA_LICENSE_KEY="set"
FA_USER_EMAIL="set"
JFROG_USER="set"
JFROG_PASS="set"
DOCKER_PASS="set"
DOCKER_USER="set"

gitlab-ci-multi-runner exec docker --docker-privileged --docker-volumes /var/run/docker.sock:/var/run/docker.sock --env "DOCKER_USER=$DOCKER_USER" --env "DOCKER_PASS=$DOCKER_PASS" --env "JFROG_USER=$JFROG_USER" --env "JFROG_PASS=$JFROG_PASS" --env "FA_LICENSE_KEY=$FA_LICENSE_KEY" --env "FA_USER_EMAIL=$FA_USER_EMAIL" build
gitlab-ci-multi-runner exec docker --docker-privileged --docker-volumes /var/run/docker.sock:/var/run/docker.sock --env "DOCKER_USER=$DOCKER_USER" --env "DOCKER_PASS=$DOCKER_PASS" --env "JFROG_USER=$JFROG_USER" --env "JFROG_PASS=$JFROG_PASS" --env "FA_LICENSE_KEY=$FA_LICENSE_KEY" --env "FA_USER_EMAIL=$FA_USER_EMAIL" test
