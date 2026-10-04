#!/usr/bin/env bash
# Installs one hardening step, restarts the OpenRGB server and checks that it
# still reports every controller it reported before. If it doesn't, the
# previous drop-ins and udev rules are restored.
#
#   sudo ./apply-stage.sh zz-20-devices.conf      # a systemd drop-in
#   sudo ./apply-stage.sh 60-openrgb.rules        # the udev rules
#   sudo ./apply-stage.sh --without "Name" 60-openrgb.rules
#                                                 # a controller is meant to go away
#   sudo ./apply-stage.sh --remove local.conf     # remove a drop-in
#   sudo ./apply-stage.sh --restore DIR           # roll back to a backup
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
dropins=/etc/systemd/system/openrgb.service.d
rules=/etc/udev/rules.d/60-openrgb.rules
backups=/root/openrgb-hardening
check=("$here/openrgb-hardening.py")

reload_udev() {
    udevadm control --reload
    udevadm trigger --action=add --subsystem-match=hidraw
    udevadm trigger --action=change --subsystem-match=usb --subsystem-match=i2c-dev
    udevadm settle
}

# Earlier rules may have handed nodes to the openrgb group; udev doesn't take
# that back when a rule disappears. Reset those nodes to the kernel/udev
# defaults so that only the rules being installed grant access again.
revoke_old_grants() {
    local node
    for node in /dev/hidraw* /dev/bus/usb/*/* /dev/i2c-*; do
        [[ -e $node ]] || continue
        if [[ $(stat -c %G "$node") == openrgb ]]; then
            chgrp root "$node"
            case $node in
                /dev/bus/usb/*) chmod 0664 "$node" ;;
                *) chmod 0600 "$node" ;;
            esac
        fi
        setfacl -x g:openrgb "$node" 2>/dev/null || true
    done
}

relabel() {
    if command -v restorecon >/dev/null; then
        restorecon -R "$dropins" "$rules" 2>/dev/null || true
    fi
}

restore() {
    local dir=$1
    [[ -d $dir/dropins ]] || { echo "$dir is not a backup" >&2; exit 1; }
    rm -rf "$dropins"
    cp -a "$dir/dropins" "$dropins"
    if [[ -e $dir/60-openrgb.rules ]]; then
        cp -a "$dir/60-openrgb.rules" "$rules"
    else
        rm -f "$rules"
    fi
    relabel
    reload_udev
    systemctl daemon-reload
    systemctl restart openrgb.service
    echo "restored $dir"
}

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

without=()
while [[ ${1-} == --without ]]; do
    without+=("${2:?controller name}")
    shift 2
done

if [[ ${1-} == --restore ]]; then
    restore "${2:?backup directory}"
    exit
fi

remove=
src=
if [[ ${1-} == --remove ]]; then
    remove=$dropins/$(basename "${2:?drop-in name}")
    [[ -e $remove ]] || { echo "no drop-in $remove" >&2; exit 1; }
    src=$remove
fi

[[ -n $src ]] || src=${1:?usage: apply-stage.sh FILE.conf|60-openrgb.rules|--remove NAME|--restore DIR}
case $src in
    *.conf) dest=$dropins/$(basename "$src") ;;
    *.rules) dest=$rules ;;
    *) echo "expected a .conf drop-in or a .rules file" >&2; exit 1 ;;
esac

expected=$(mktemp)
trap 'rm -f "$expected"' EXIT
python3 "${check[@]}" devices >"$expected"
if [[ ! -s $expected ]]; then
    echo "the server reports no controllers; fix that before hardening further" >&2
    exit 1
fi
echo "controllers before:"
sed 's/^/  /' "$expected"
for name in "${without[@]}"; do
    grep -qxF -- "$name" "$expected" || { echo "no controller named '$name'" >&2; exit 1; }
    grep -vxF -- "$name" "$expected" >"$expected.new" || true
    mv "$expected.new" "$expected"
    echo "expected to disappear: $name"
done

backup=$backups/$(date +%Y%m%d-%H%M%S)
mkdir -p "$backup"
chmod 700 "$backups"
cp -a "$dropins" "$backup/dropins"
[[ -e $rules ]] && cp -a "$rules" "$backup/"
echo "backup: $backup"

if [[ -n $remove ]]; then
    rm "$remove"
else
    install -m 0644 "$src" "$dest"
    relabel
fi
if [[ $dest == "$rules" ]]; then
    revoke_old_grants
    reload_udev
fi
systemctl daemon-reload
systemd-analyze verify openrgb.service 2>&1 | grep -i openrgb || true
systemctl restart openrgb.service || true

# The server must also still run as the openrgb account: removing the wrong
# drop-in would bring back the packaged unit's root service.
if systemctl is-active --quiet openrgb.service &&
    [[ $(systemctl show -p User --value openrgb.service) == openrgb ]] &&
    python3 "${check[@]}" devices --expect-file "$expected"; then
    echo "$([[ -n $remove ]] && echo removed || echo installed) $dest"
    reported=$(python3 "${check[@]}" devices)
    for name in "${without[@]}"; do
        if grep -qxF -- "$name" <<<"$reported"; then
            echo "note: '$name' is still reported" >&2
        fi
    done
    journalctl -u openrgb.service -b -n 20 --no-pager | grep -v "recv_select failed receiving magic" || true
    echo "Now check lighting from Artemis. To undo: sudo $0 --restore $backup"
else
    journalctl -u openrgb.service -b -n 50 --no-pager
    restore "$backup"
    exit 1
fi
