# Edit this configuration file to define what should be installed on
# your system. Help is available in the configuration.nix(5) man page, on
# https://search.nixos.org/options and in the NixOS manual (`nixos-help`).

{ config, lib, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  networking.hostName = "ds9"; # Define your hostname.
  # Pick only one of the below networking options.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.
  # networking.networkmanager.enable = true;  # Easiest to use and most distros use this by default.
  networking = {
    interfaces.enp6s18 = {
      ipv4.addresses = [{
        address = "10.0.0.100";
        prefixLength = 8;
      }];
    };
    defaultGateway = {
      address = "10.0.0.1";
      interface = "enp6s18";
    };
    nameservers = [ "9.9.9.9" ];
    useDHCP = false;
  };

  security.sudo.execWheelOnly = true;
  security.sudo.extraConfig = ''
    Defaults lecture = never
  '';
  nix.settings.allowed-users = [ "@wheel" ];

  environment.etc."machine-id".source = "/persist/etc/machine-id";

  # Set your time zone.
  time.timeZone = "Europe/Paris";

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Select internationalisation properties.
  # i18n.defaultLocale = "en_US.UTF-8";
  # console = {
  #   font = "Lat2-Terminus16";
  #   keyMap = "us";
  #   useXkbConfig = true; # use xkb.options in tty.
  # };

  # Enable the X11 windowing system.
  # services.xserver.enable = true;




  # Configure keymap in X11
  # services.xserver.xkb.layout = "us";
  # services.xserver.xkb.options = "eurosign:e,caps:escape";

  # Enable CUPS to print documents.
  # services.printing.enable = true;

  # Enable sound.
  # hardware.pulseaudio.enable = true;
  # OR
  # services.pipewire = {
  #   enable = true;
  #   pulse.enable = true;
  # };

  # Enable touchpad support (enabled default in most desktopManager).
  # services.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  # users.users.alice = {
  #   isNormalUser = true;
  #   extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.
  #   packages = with pkgs; [
  #     firefox
  #     tree
  #   ];
  # };

  users.mutableUsers = false;
  users.users."amoutill" = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];

    openssh.authorizedKeys.keys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID1SYyLecS2vZgHClsxjMIF9R895CepgDg1Y1aJklOoe openpgp:0x453A8058" ];
    # mkpasswd -m sha-512 "<password>"
    hashedPasswordFile = "/persist/passwords/amoutill";

    packages = with pkgs; [
      git
    ];
  };


  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    neovim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
  ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
    settings.ChallengeResponseAuthentication = false;
    extraConfig = ''
      AllowTcpForwarding yes
      X11Forwarding no
      AllowAgentForwarding no
      AllowStreamLocalForwarding no
      AuthenticationMethods publickey
    '';
    hostKeys = [
      {
        bits = 4096;
        path = "/persist/etc/ssh/ssh_host_rsa_key";
        type = "rsa";
      }
      {
        path = "/persist/etc/ssh/ssh_host_ed25519_key";
        type = "ed25519";
      }
    ];
  };

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  networking.firewall.enable = true;

  services.tailscale.enable = true;
  networking.firewall.trustedInterfaces = [ "tailscale0" ];

  environment.persistence."/persist" = {
    hideMounts = true;
    directories = [
      "/var/lib/tailscale"
      "/var/lib/nixos"
    ];
  };
  services.openldap = {
    enable = true;
    settings = {
      children = {
        "cn=schema".includes = [
          "${pkgs.openldap}/etc/schema/core.ldif"
          "${pkgs.openldap}/etc/schema/cosine.ldif"
          "${pkgs.openldap}/etc/schema/inetorgperson.ldif"
          "${pkgs.openldap}/etc/schema/nis.ldif"
        ];
        "olcDatabase={1}mdb" = {
          attrs = {
            objectClass = [ "olcDatabaseConfig" "olcMdbConfig" ];
            olcDatabase = "{1}mdb";
            olcDbDirectory = "/var/lib/openldap/db";
            olcSuffix = "dc=amoutillon,dc=com";
            olcRootDN = "cn=admin,dc=amoutillon,dc=com";
            olcAccess = [
              /* custom access rules for userPassword attributes */
              ''{0}to attrs=userPassword
                  by self write
                  by anonymous auth
                  by * none''

              /* allow read on anything else for users, deny for anyone else */
              ''{1}to *
                  by users read
                  by * none''
            ];
          };
        };
      };
    };
    declarativeContents = {
      "dc=amoutillon,dc=com" = ''
        dn: dc=amoutillon,dc=com
        objectClass: top
        objectClass: dcObject
        objectClass: organization
        o: amoutillon.com

        dn: ou=users,dc=amoutillon,dc=com
        objectClass: organizationalUnit
        ou: users

        dn: ou=groups,dc=amoutillon,dc=com
        objectClass: organizationalUnit
        ou: groups

        dn: cn=admins,ou=groups,dc=amoutillon,dc=com
        objectClass: posixGroup
        cn: admins
        gidNumber: 10000

        dn: cn=test,ou=groups,dc=amoutillon,dc=com
        objectClass: posixGroup
        cn: test
        gidNumber: 11000

        dn: uid=test,ou=users,dc=amoutillon,dc=com
        objectClass: inetOrgPerson
        objectClass: posixAccount
        objectClass: organizationalPerson
        uid: test
        sn: Moutillon
        givenName: Axel
        cn: test
        uidNumber: 11000
        gidNumber: 11000
        homeDirectory: /home/test
        userPassword: ${builtins.readFile /persist/passwords/ldap/amoutill}
      '';
    };
  };
  
  services.sssd = {
    enable = true;
    config = ''
      [sssd]
      services = nss, pam
      config_file_version = 2

      [domain/ldap]
      id_provider = ldap
      auth_provider = ldap
      ldap_uri = "ldap://localhost"
      ldap_search_base = "dc=amoutillon,dc=com"

      # Configuration for using user's credentials directly
      # Do not specify a bind_dn or bind_password
      # Set user and group search bases as needed
      ldap_user_search_base = "ou=users,dc=amoutillon,dc=com"
      ldap_group_search_base = "ou=groups,dc=amoutillon,dc=com"
    '';
  };


  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true; # Unsupported with flakes

  # This option defines the first version of NixOS you have installed on this particular machine,
  # and is used to maintain compatibility with application data (e.g. databases) created on older NixOS versions.
  #
  # Most users should NEVER change this value after the initial install, for any reason,
  # even if you've upgraded your system to a new NixOS release.
  #
  # This value does NOT affect the Nixpkgs version your packages and OS are pulled from,
  # so changing it will NOT upgrade your system - see https://nixos.org/manual/nixos/stable/#sec-upgrading for how
  # to actually do that.
  #
  # This value being lower than the current NixOS release does NOT mean your system is
  # out of date, out of support, or vulnerable.
  #
  # Do NOT change this value unless you have manually inspected all the changes it would make to your configuration,
  # and migrated your data accordingly.
  #
  # For more information, see `man configuration.nix` or https://nixos.org/manual/nixos/stable/options#opt-system.stateVersion .
  system.stateVersion = "24.05"; # Did you read the comment?

}
