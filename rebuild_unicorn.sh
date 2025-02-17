cd emulator
echo "[*] Rebuilding Unicorn"
pushd unicorn; UNICORN_DEBUG=yes USERNAME=`whoami` ./build_unicorn.sh || { popd; exit 1; }; popd

echo "[*] Building native harness module"
make -C harness/fuzzware_harness/native clean all "$@" || exit 1

echo "[*] Installing harness"
pushd harness; pip3 install -e . || { popd; exit 1; }; popd
cd ~/fuzzware_repo
