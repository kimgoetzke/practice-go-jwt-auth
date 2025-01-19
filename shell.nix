{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  name = "A Go Development Environment";
  nativeBuildInputs = with pkgs; [
    go
    go-swag
    go-tools
    openssl
    # delve
    # ginkgo
  ];
  shellHook = ''
    export GOPATH=${pkgs.go}/go;
    export GOROOT=${pkgs.go}/bin;
    echo ""
    echo "Welcome to your Go development environment!" | ${pkgs.lolcat}/bin/lolcat
    echo ""
  '';
}
