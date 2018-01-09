with import <nixpkgs> {};

stdenv.mkDerivation rec {
 name = "build";
 env = buildEnv {
   name = name;
   paths = buildInputs;
 };

 buildInputs = [
   docker
   direnv
   git
   gitlab-runner
 ];

 FLUIDASSERTS_USER_EMAIL = "set";
 FLUIDASSERTS_LICENSE_KEY  = "set";
 DOCKER_PASS = "set";
 DOCKER_USER = "set";
 PYPI_USER="set";
 PYPI_PASS="set";

}
