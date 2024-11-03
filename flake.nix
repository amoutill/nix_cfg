{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    impermanence.url = "github:nix-community/impermanence";
  };
  outputs = { self, nixpkgs, impermanence, ... }: {
    nixosConfigurations.ds9 = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
	    impermanence.nixosModules.impermanence
	    ./hosts/ds9/configuration.nix
	  ];
    };
  };
}
