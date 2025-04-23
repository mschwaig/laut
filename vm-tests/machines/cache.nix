{
  system,
  nixpkgs,
  lib,
  pkgsIA,
  cachePort,
  cacheStoreUrl,
  cacheAccessKey,
  cacheSecretKey,
  ...
}:

{
  virtualisation.writableStore = true;
  virtualisation.memorySize = 2048;
  virtualisation.cores = 2;
  environment.systemPackages = [ pkgsIA.minio-client ];
  nix.extraOptions = "experimental-features = nix-command";
  services.minio = {
    enable = true;
    region = "eu-west-1";
    listenAddress = "127.0.0.1:9002";
    rootCredentialsFile = pkgsIA.writeText "minio-credentials" ''
      MINIO_ROOT_USER=${cacheAccessKey}
      MINIO_ROOT_PASSWORD=${cacheSecretKey}
    '';
  };

  environment.variables = {
    AWS_ACCESS_KEY_ID = cacheAccessKey;
    AWS_SECRET_ACCESS_KEY = cacheSecretKey;
  };

  services.caddy = {
    enable = true;
    virtualHosts."http://cache:9000" = {
      extraConfig = ''
        reverse_proxy localhost:9002
      '';
    };
  };

  networking.firewall.allowedTCPPorts = [
    cachePort
    9001
  ];
}
