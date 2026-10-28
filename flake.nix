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
            '';
          };
        });
    };
}
