#!/bin/bash
set -eo pipefail
lab_dir="$(cd "$(dirname "$0")" && pwd)"
zephyr_workspace="${LAB_ZEPHYR_WORKSPACE:-$HOME/zephyrproject}"
build_root="${LAB_BUILD_ROOT:-/private/tmp/ese5180-iot-security-$UID}"
mode="${1:-client}"
case "$mode" in
  client) app_name=LoRa_Encrypted_Client_Zephyr ;;
  server) app_name=LoRa_Encrypted_Server_Zephyr ;;
  aes-sw_ram|aes-sw_rom|aes-sw_rom_fewer|aes-hw) app_name=AES_Benchmark_Zephyr ;;
  huk-plain|huk-secure) app_name=Hardware_Unique_Keys ;;
  *) echo 'Usage: bash build.sh client|server|aes-sw_ram|aes-sw_rom|aes-sw_rom_fewer|aes-hw|huk-plain|huk-secure'; exit 2 ;;
esac
export PATH="$zephyr_workspace/.venv/bin:$PATH"
export ZEPHYR_BASE="$zephyr_workspace/zephyr"
export ZEPHYR_SDK_INSTALL_DIR="${LAB_ZEPHYR_SDK:-$HOME/zephyr-sdk-1.0.1}"
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export CCACHE_DIR="$build_root/.ccache"
export PYTHONNOUSERSITE=1
mkdir -p "$build_root/sources" "$lab_dir/evidence" "$lab_dir/firmware/$mode"
# Keep authoritative sources here; stage them without spaces for Zephyr/Kconfig.
for folder in "$app_name" Crypto common; do
  [[ -d "$lab_dir/lab2_security/$folder" ]] || continue
  mkdir -p "$build_root/sources/$folder"
  rsync -a --delete "$lab_dir/lab2_security/$folder/" "$build_root/sources/$folder/"
done
extra_args=()
case "$mode" in
  aes-*) extra_args+=("-DEXTRA_CONF_FILE=${mode#aes-}.conf") ;;
  huk-plain) extra_args+=("-DEXTRA_CONF_FILE=plain.conf") ;;
  huk-secure) extra_args+=("-DEXTRA_CONF_FILE=secure.conf") ;;
esac
cd "$zephyr_workspace"
west build -p auto -b nucleo_wl55jc \
  -d "$build_root/build/$mode" "$build_root/sources/$app_name" -- \
  "-DUSER_CACHE_DIR=$build_root/.cache" "${extra_args[@]}" 2>&1 | tee "$lab_dir/evidence/build-$mode.log"
for artifact in zephyr.elf zephyr.hex zephyr.bin .config; do
  if [[ -f "$build_root/build/$mode/zephyr/$artifact" ]]; then
    cp "$build_root/build/$mode/zephyr/$artifact" "$lab_dir/firmware/$mode/"
  fi
done
echo "Build directory: $build_root/build/$mode"
