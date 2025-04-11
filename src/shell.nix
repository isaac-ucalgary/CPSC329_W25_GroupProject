# shell.nix
let
  pkgs = import <nixpkgs> {};

  python = pkgs.python3Full.override {
    self = python;
    # packageOverrides = pyfinal: pyprev: {
    #   # mysql-connector = pyfinal.callPackage package-mysql-connector { };
    # };
  };
in
  pkgs.mkShell {
    packages = with pkgs; [
      (python.withPackages (
        python-pkgs:
          with python-pkgs; [
            # select Python packages here
            # matplotlib
          ]
      ))
    ];

    shellHook = '''';
  }
