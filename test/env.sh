
export PROJECT_DIR=$(git rev-parse --show-toplevel)

# Container (docker)
export NET_IP="172.30.216.0/16"
export NET_NAME="fluidasserts_fluidasserts"
export SERVICE="container"
export IP="172.30.216.100"

# Setup (ansible)
export ANSIBLE_HOSTS="$PROJECT_DIR"/test/provision/hosts
export ANSIBLE_CONFIG="$PROJECT_DIR"/test/provision/config.cfg
export ANSIBLE_SCP_IF_SSH=y

# Desahibilitar agentes SSH
export SSH_AUTH_SOCK=0

