{
  pkgs,
  ...
}:
{
  # https://devenv.sh/languages/
  languages.go = {
    enable = true;
  };

  scripts.release = {
    description = "Build statically linked release binaries into releases/";
    packages = [ pkgs.coreutils ];
    exec = ''
      set -euo pipefail

      rm -rf releases
      mkdir -p releases

      for target in \
        linux/amd64 \
        linux/arm64 \
        darwin/amd64 \
        darwin/arm64 \
        windows/amd64 \
        windows/arm64
      do
        goos="''${target%/*}"
        goarch="''${target#*/}"
        ext=""
        if [ "$goos" = "windows" ]; then
          ext=".exe"
        fi

        out="releases/unaware-''${goos}-''${goarch}''${ext}"
        echo "building ''${out}"
        CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
          go build -buildvcs=false -trimpath -ldflags "-s -w" -o "$out" .
      done
    '';
  };

  enterShell = ''
    go version
  '';
}

