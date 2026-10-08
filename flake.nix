{
  description = "Trapdoor: Install-Time Behavior Auditor";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python313;
      in {
        devShells.default = pkgs.mkShell {
          name = "trapdoor-dev";
          buildInputs = with pkgs; [
            cmake
            gnumake
            gcc
            gdb
            python
            python.pkgs.pytest
            python.pkgs.pytest-cov
            pkg-config
            nodejs # npm + node for M1 acceptance (offline local-package install)
          ];
          shellHook = ''
            echo "trapdoor dev shell (system: ${system})"
            echo "  cmake $(cmake --version | head -1)"
            echo "  $(g++ --version | head -1)"
            echo "  $(python --version 2>&1)"
          '';
        };
      });
}
