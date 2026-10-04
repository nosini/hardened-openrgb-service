# hardened-openrgb-service

Runs OpenRGB's packaged `openrgb.service` as a dedicated `openrgb` system
account, listening on `127.0.0.1:6742` with its state in `/var/lib/openrgb`,
and narrows it down to the HID interfaces of the RGB controllers it actually
drives and the SDK listener. A desktop client such as Artemis talks to the
server over the SDK and needs no device permissions of its own.

The SDK has no client authentication. Binding to loopback keeps remote hosts
out, but every local process can still connect and change lighting. What this
setup protects is the hardware: no desktop process gets raw access to
keyboards or other HID devices, and the server itself can reach only its RGB
interfaces.

## Files

- `openrgb-hardening.py` has three subcommands. `check` prints a read-only
  report on the service, its process, the listener, every hidraw node, keyboard
  event nodes, I2C and raw USB nodes, udev rules, desktop autostart entries
  and recent denials. `devices` lists the controllers the server reports over
  the SDK; it only reads and doesn't change any lighting. `udev-rules` prints
  udev rules for the interfaces the running server has open, or for a first
  install, for the supported devices that are connected.
- `apply-stage.sh` installs or removes one drop-in, or installs the udev
  rules, then restarts the server. It checks that the server still runs as
  `openrgb` and still reports every controller it reported before. If not, it
  restores the previous configuration. Each run keeps a backup under
  `/root/openrgb-hardening/`.
- `openrgb.sysusers` creates the `openrgb` account.
- `zz-10-service.conf` runs the packaged service as that account, on loopback,
  with its configuration in `/var/lib/openrgb`.
- `zz-20-devices.conf`, `zz-30-network.conf`, `zz-40-filesystem.conf` and
  `zz-50-syscalls.conf` restrict it. The `zz-` prefix sorts all drop-ins after
  any existing local one, so their settings take precedence.

## Run the server under its own account

```sh
sudo install -m 644 openrgb.sysusers /etc/sysusers.d/openrgb.conf
sudo systemd-sysusers /etc/sysusers.d/openrgb.conf
sudo mkdir -p /etc/systemd/system/openrgb.service.d
sudo install -m 644 zz-10-service.conf /etc/systemd/system/openrgb.service.d/
sudo systemctl daemon-reload
sudo systemctl enable --now openrgb.service
```

Profiles saved by an earlier root service stay in `/etc/openrgb`. Copy any you
want into `/var/lib/openrgb` and `chown` them to `openrgb`.

If an existing drop-in of your own already does what `zz-10-service.conf`
does, install the new file first and then remove the old one. Both steps check
that the server keeps running as `openrgb` and keeps its controllers:

```sh
sudo ./apply-stage.sh zz-10-service.conf
sudo ./apply-stage.sh --remove local.conf
```

## Before you start

Run the check from the desktop account. It uses `$SUDO_USER` to find the
desktop user:

```sh
sudo ./openrgb-hardening.py check
```

Every `WARN` line is worth a look. With the packaged OpenRGB rules, you'll
typically see `openrgb can open /dev/hidrawN ... which the server doesn't use`
for many interfaces, sometimes including the keyboard interfaces of the
keyboard whose lighting it controls.

Disable autostart entries for an OpenRGB instance under the desktop account,
if the check lists any. Move them aside instead of deleting them:

```sh
mkdir -p ~/.config/autostart-disabled
mv ~/.config/autostart/OpenRGB.desktop ~/.config/autostart-disabled/
systemctl --user disable --now openrgb.service
```

## Grant only the interfaces in use

udev rules work on stable identities: USB vendor ID, product ID and interface
number. They don't depend on the `/dev/hidrawN` numbers, which change between
boots and replugs.

On a fresh install, the packaged rules grant devices only to the logged-in
desktop user, so the `openrgb` account can't open anything yet. Start with
rules for every interface of the connected devices that OpenRGB supports,
leaving out interfaces that carry keyboard, mouse or media-key input:

```sh
sudo ./openrgb-hardening.py udev-rules --bootstrap > 60-openrgb.rules
sudo install -m 644 60-openrgb.rules /etc/udev/rules.d/
sudo udevadm control --reload
sudo udevadm trigger --action=add --subsystem-match=hidraw
sudo systemctl restart openrgb.service
```

Once the server is running and has detected all of its controllers, generate
rules for exactly the interfaces it has open:

```sh
sudo ./openrgb-hardening.py udev-rules > 60-openrgb.rules
cat 60-openrgb.rules
```

The generated file goes to `/etc/udev/rules.d/60-openrgb.rules`, which shadows
the packaged file of the same name. Everything the packaged rules granted,
including `uaccess` and I2C access, is gone; only the listed interfaces get
`root:openrgb 0660`. The file is generated per machine and is kept out of the
repository by `.gitignore`.

The generator refuses an interface whose HID descriptor also has a keyboard,
mouse or media-key collection. A hidraw node delivers every report of its
interface, so granting such an interface lets the server read that input. If
the lighting really is on such an interface, `--allow-input` accepts it.
File permissions can't split one hidraw node.

```sh
sudo ./apply-stage.sh 60-openrgb.rules
```

udev doesn't take back permissions when a rule disappears, so before applying
the new rules, `apply-stage.sh` resets every node the `openrgb` group owns or
has an ACL entry on. The server's controllers come back only if the new rules
grant them again.

### Leaving a controller out

OpenRGB also detects controllers that have nothing to light, such as a
motherboard RGB controller with no LEDs or strips attached. To drop one,
exclude its USB vendor and product ID (shown by `check`, and in the comments of
the generated rules) and tell `apply-stage.sh` that its name is meant to
disappear:

```sh
sudo ./openrgb-hardening.py udev-rules --exclude VID:PID > 60-openrgb.rules
sudo ./apply-stage.sh --without "Controller name" 60-openrgb.rules
```

`--exclude VID:PID:IF` drops a single interface instead. Once the server can't
open the device, it no longer detects it, so later runs of `udev-rules` leave
it out without `--exclude`.

## systemd restrictions

Apply the drop-ins one at a time and test lighting from the SDK client after
each step:

```sh
sudo ./apply-stage.sh zz-20-devices.conf
sudo ./apply-stage.sh zz-30-network.conf
sudo ./apply-stage.sh zz-40-filesystem.conf
sudo ./apply-stage.sh zz-50-syscalls.conf
```

- Devices: the device cgroup allows hidraw plus the standard pseudo-devices.
  `PrivateDevices=` can't be used because it hides hidraw nodes, and binding
  individual nodes would tie the unit to boot-specific numbers.
- Network: IPv4 TCP only, bound to port 6742, with traffic limited to
  `127.0.0.1` on `lo`. `AF_UNIX` is not allowed, so the server can't reach
  D-Bus or abstract Unix sockets.
- Filesystem: host `/run` and `/var` are hidden, except the service's state and
  runtime directories and the udev database. Home directories, `/boot`, `/mnt`,
  `/media`, `/srv` and `/opt` are hidden as well. Everything the server can
  write is mounted noexec, which also stops OpenRGB plugins from loading out of
  its state directory.
- System calls: no capabilities, `NoNewPrivileges`, no W+X memory, and
  `@system-service` without `@privileged` and `@resources`.

The server can still open connections to other services on `127.0.0.1`;
systemd's address filters can't restrict which loopback ports it reaches.

The address, interface and socket-bind filters and the device cgroup need
cgroup BPF support. If BPF is unavailable, systemd only logs a warning and
starts the service anyway. `check` shows those warnings from the journal.

## Reboot and verify

```sh
sudo ./openrgb-hardening.py check --expect N
```

where N is the number of controllers. The check confirms the
following:

- The server runs as `openrgb` with no capabilities, `NoNewPrivs` and a seccomp
  filter.
- The only listener is `127.0.0.1:6742`.
- The server's hidraw nodes are `root:openrgb 0660` with no ACLs.
- `openrgb` can't open any other hidraw node, and neither it nor the desktop
  user can open keyboard event nodes, I2C or `uinput`.
- The desktop user is not in `input` or `openrgb`.
- No OpenRGB runs under the desktop account.

Then change lighting on every device from the SDK client.

## Rolling back

Each `apply-stage.sh` run prints its backup directory. That directory holds the
drop-ins and udev rules from before the step:

```sh
sudo ./apply-stage.sh --restore /root/openrgb-hardening/YYYYMMDD-HHMMSS
```

To remove a single drop-in:

```sh
sudo rm /etc/systemd/system/openrgb.service.d/zz-40-filesystem.conf
sudo systemctl daemon-reload
sudo systemctl restart openrgb.service
```

If a step fails, keep its journal output and fix only the restriction that
caused the failure. Don't solve it by adding capabilities, widening device
access or switching SELinux to permissive.
