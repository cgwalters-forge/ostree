#!/bin/sh
# SPDX-License-Identifier: LGPL-2.0+
#
# Undo ostree-fips-boot-mount.sh after the FIPS check, so that the generator's
# boot.mount stays the only mount of /boot in the booted system.

command -v getarg > /dev/null || . /lib/dracut-lib.sh

if [ -f /tmp/ostree-fips-boot-mounted ]; then
    umount "$NEWROOT/boot" || warn "ostree: Failed to unmount $NEWROOT/boot after the FIPS check"
    rm -f /tmp/ostree-fips-boot-mounted
fi
