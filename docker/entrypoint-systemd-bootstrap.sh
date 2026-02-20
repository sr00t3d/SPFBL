#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP_UNIT_SRC="/home/spfbl/docker/spfbl-bootstrap.service"
BOOTSTRAP_UNIT_DST="/etc/systemd/system/spfbl-bootstrap.service"
BOOTSTRAP_WANTS="/etc/systemd/system/multi-user.target.wants/spfbl-bootstrap.service"

if [ -f "$BOOTSTRAP_UNIT_SRC" ]; then
  cp -f "$BOOTSTRAP_UNIT_SRC" "$BOOTSTRAP_UNIT_DST"
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sf "$BOOTSTRAP_UNIT_DST" "$BOOTSTRAP_WANTS"
fi

exec /sbin/init
