#!/bin/sh
# SPDX-License-Identifier: LGPL-2.0+
#
# When /boot is a directory on the physical root, the dracut fips module's
# kernel HMAC check (pre-pivot 01, fips-noboot.sh) reads $NEWROOT/boot,
# but /boot is only bind-mounted from /sysroot/boot by the boot.mount
# that ostree-system-generator writes, which takes effect after switch-root.
# Bind-mount it read-only just for the check; ostree-fips-boot-umount.sh
# removes it again at pre-pivot 02.

command -v getarg > /dev/null || . /lib/dracut-lib.sh

# Like the generator, a boot/loader symlink means /boot is on the physical root.
# With boot=, the fips module mounts /boot itself.
if fipsmode=$(getarg fips) && [ -n "$fipsmode" ] && [ "$fipsmode" != "0" ] \
    && ! getarg boot= > /dev/null \
    && [ -L "$NEWROOT/sysroot/boot/loader" ] && [ -d "$NEWROOT/boot" ] \
    && ! ismounted "$NEWROOT/boot"; then
    if mount -o ro --bind "$NEWROOT/sysroot/boot" "$NEWROOT/boot"; then
        : > /tmp/ostree-fips-boot-mounted
    else
        warn "ostree: Failed to bind-mount $NEWROOT/sysroot/boot for the FIPS check"
    fi
fi
