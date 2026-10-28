{
  description = "KM003C Rust development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
    in {
      devShells = nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          libraries = with pkgs; [
            wayland
            libxkbcommon
            vulkan-loader
            libGL
            libX11
            libXcursor
            libXi
            libXrandr
          ];
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [ rustup pkg-config just uv ];
            buildInputs = libraries;
            shellHook = ''
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath libraries}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
              if [ -z "''${SSL_CERT_FILE:-}" ]; then
                if [ -n "''${NIX_SSL_CERT_FILE:-}" ]; then
                  export SSL_CERT_FILE="$NIX_SSL_CERT_FILE"
                elif [ -r /etc/ssl/certs/ca-certificates.crt ]; then
                  export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
                else
                  export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                fi
              fi
            '';
          };
        });
    };
}
