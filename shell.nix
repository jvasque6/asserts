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

 DOCKER_PASS = "set";
 DOCKER_USER = "set";
}
