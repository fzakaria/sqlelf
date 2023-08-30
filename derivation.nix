{ poetry2nix, poetryOverrides }:
poetry2nix.mkPoetryApplication {
  projectDir = ./.;
  overrides = poetry2nix.overrides.withDefaults poetryOverrides;
}
