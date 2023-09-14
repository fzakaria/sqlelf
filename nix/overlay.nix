self: super: {

  sqlelf = self.callPackage ./derivation.nix { };

  sqlelf-env = self.poetry2nix.mkPoetryEnv {
    projectDir = ../.;
    overrides = self.poetry2nix.overrides.withDefaults self.poetryOverrides;
    editablePackageSources = { sqlelf = ./sqlelf; };
  };

  sqlite-3430 = self.sqlite.overrideAttrs (oldAttrs: rec {
    version = "3.43.0";
    src = self.fetchurl {
      url = "https://sqlite.org/2023/sqlite-autoconf-3430000.tar.gz";
      sha256 = "sha256-SQCNvzr8BNTtyOz8NOTq0ZaXMDQpPJl62tL2PwF2KuE=";
    };
  });


  lief-3414ded = self.callPackage ./lief.nix { python = self.python3; };

  poetryOverrides = self: super: {
    lief = super.toPythonModule super.pkgs.lief-3414ded.py;

    sh = super.sh.overridePythonAttrs (old: {
      buildInputs = (old.buildInputs or [ ]) ++ [ super.poetry ];
    });

    apsw = super.apsw.overridePythonAttrs (old: rec {
      version = "3.43.1.0";
      src = super.pkgs.fetchFromGitHub {
        owner = "rogerbinns";
        repo = "apsw";
        rev = "refs/tags/${version}";
        sha256 = "sha256-x+bSft37DgF2tXXCL6ac86g1+mj/wJeDLoCSiVSXedA=";
      };
      buildInputs = (old.buildInputs or [ ]) ++ [ super.pkgs.sqlite-3430 ];
    });
  };
}
