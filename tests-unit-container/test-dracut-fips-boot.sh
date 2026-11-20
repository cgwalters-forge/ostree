#!/bin/bash
# Tests the dracut pre-pivot hooks that expose /boot to the fips module's
# kernel HMAC check when /boot is on the physical root. The hooks are
# sourced with stubs for the dracut-lib functions they use.

set -xeuo pipefail

# Ensure this isn't run accidentally
test "${TEST_CONTAINER}" = 1

moddir=/usr/lib/dracut/modules.d/50ostree
marker=/tmp/ostree-fips-boot-mounted
export NEWROOT=/newroot

cleanup() {
	if mountpoint -q "$NEWROOT/boot"; then
		umount "$NEWROOT/boot"
	fi
	rm -rf "$NEWROOT" "$marker"
}
trap cleanup EXIT

cmdline=
getarg() {
	local arg
	for arg in $cmdline; do
		case "$1" in
			*=) case "$arg" in "$1"*) echo "${arg#"$1"}"; return 0 ;; esac ;;
			*) case "$arg" in "$1"=*) echo "${arg#"$1"=}"; return 0 ;; "$1") return 0 ;; esac ;;
		esac
	done
	return 1
}
ismounted() { mountpoint -q "$1"; }
warn() { echo "warn: $*" >&2; }

assert_not_mounted() {
	if mountpoint -q "$1"; then
		echo "error: $1 should not be a mountpoint" >&2
		exit 1
	fi
}

# Run the mount hook and check whether it mounted /boot, then run the
# unmount hook and check it is gone again.
check_hooks() {
	local expect=$1
	. "$moddir/ostree-fips-boot-mount.sh"
	if test "$expect" = mounted; then
		mountpoint "$NEWROOT/boot"
		test -f "$NEWROOT/boot/ostree/default-1234/.vmlinuz-1.0.hmac"
		[[ "$(findmnt -n -o OPTIONS "$NEWROOT/boot")" == ro,* ]]
		test -f "$marker"
	else
		assert_not_mounted "$NEWROOT/boot"
		test '!' -f "$marker"
	fi
	. "$moddir/ostree-fips-boot-umount.sh"
	assert_not_mounted "$NEWROOT/boot"
	test '!' -f "$marker"
}

# A deployment root with the physical root at sysroot, /boot on the same
# partition (boot/loader is a symlink) and an empty boot directory.
mkdir -p "$NEWROOT"/{boot,sysroot/boot/loader.0,sysroot/boot/ostree/default-1234}
ln -s loader.0 "$NEWROOT/sysroot/boot/loader"
touch "$NEWROOT/sysroot/boot/ostree/default-1234/.vmlinuz-1.0.hmac"

cmdline="fips=1 root=UUID=cafebabe"
check_hooks mounted
echo "ok fips with /boot on the root filesystem"

for cmdline in "root=UUID=cafebabe" "fips=0" "fips=1 boot=UUID=cafebabe"; do
	check_hooks unmounted
done
echo "ok no mount without fips=1 or with boot="

# An existing mount of /boot is left alone.
cmdline="fips=1"
mount --bind "$NEWROOT/sysroot/boot/loader.0" "$NEWROOT/boot"
. "$moddir/ostree-fips-boot-mount.sh"
test '!' -f "$marker"
umount "$NEWROOT/boot"
echo "ok existing /boot mount left alone"

# A separate /boot partition has no boot/loader symlink on the physical root.
rm "$NEWROOT/sysroot/boot/loader"
check_hooks unmounted
echo "ok no mount with a separate /boot"
