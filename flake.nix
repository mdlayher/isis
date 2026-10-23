{
  description = "Development environment for github.com/mdlayher/isis";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            # go.mod's language version floor is what this must
            # satisfy; bump alongside it.
            pkgs.go_1_27
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
            # The interop suite's oracle. This FRR must match the
            # frrVersion pin in interop/frr.go, and flake.lock is what
            # holds it there.
            pkgs.frr
          ];
        };
      });
    };
}
