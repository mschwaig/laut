{
  system,
  pkgs,
  lib,
  cachePort,
  cacheStoreUrl,
  ...
}:

let
  # Cache server is purely infra: the HTTP cache server doesn't depend on the
  # package-under-test, so it lives on the rolling infra pkgs.
  httpCacheServer = pkgs.writeShellScriptBin "http-cache-server" ''
    exec ${pkgs.python3}/bin/python3 ${../http-cache-server.py}
  '';
in

{
  virtualisation.writableStore = true;
  virtualisation.memorySize = 2 * 1024;
  virtualisation.cores = 2;
  nix.extraOptions = "experimental-features = nix-command";

  systemd.services.http-cache-server = {
    description = "HTTP binary cache server with PUT support";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      ExecStart = "${httpCacheServer}/bin/http-cache-server";
      User = "root";
      Group = "root";
    };
  };

  networking.firewall.allowedTCPPorts = [
    cachePort
  ];
}
