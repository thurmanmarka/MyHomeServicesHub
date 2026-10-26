# MariaDB backups

Nightly backup of every application database on the Pi (`hub_db`, `snmp_db`,
`wifi_db`, and any added later) plus MariaDB's users and grants, and the files
listed in `EXTRA_FILES` (Wi-Fi Control's `secrets.json` and `secret.key`).

- Runs at about 03:30 from a systemd timer; if the Pi was off, it runs at the next boot.
- Writes `/mnt/hdd/backups/mariadb/YYYY-MM-DD/<db>.sql.gz` and keeps the newest 14 days.
- Mirrors that folder to the NAS's NFS share (`\\ThurmanServer\Thurman Storage\db_backups\mariadb`,
  next to the weewx backups), only after checking the share really is mounted.
- A dump that fails or is cut short fails the whole run (visible in `systemctl status`),
  and the previous good backup is left alone.

The backups contain password hashes, SNMP community strings, and Wi-Fi
Control's saved secrets together with the key that decrypts them: they are
written readable by root only, and the NAS folder must stay private too.

## Files

| File | Install as |
|---|---|
| `mariadb-backup.sh` | `/usr/local/bin/mariadb-backup.sh` |
| `mariadb-backup.service` | `/etc/systemd/system/mariadb-backup.service` |
| `mariadb-backup.timer` | `/etc/systemd/system/mariadb-backup.timer` |
| `mariadb-backup.default` | `/etc/default/mariadb-backup` (settings) |

## Setup

### 1. On the NAS

The `Thurman Storage` share is already exported over NFS for the weewx Pi. In
the share's **NFS Permissions**, add a rule for this Pi's IP address with the
same settings as the weewx Pi's rule (read/write, same squash option).

### 2. Mount the share on this Pi

Like the weewx Pi (which mounts `db_backups/weewx`), this Pi mounts only its own
folder. First create `db_backups\mariadb` on the share (e.g. from Windows:
`\\ThurmanServer\Thurman Storage\db_backups\mariadb`), then add to `/etc/fstab`:

```
192.168.86.5:/volume1/Thurman\040Storage/db_backups/mariadb /mnt/synology_backup nfs defaults,noatime,_netdev,nofail,x-systemd.automount,x-systemd.idle-timeout=600 0 0
```

(`\040` is the space in "Thurman Storage". `nofail` + `automount` keep a NAS
outage from blocking the Pi's boot; the share mounts when first used.)

```bash
sudo apt install -y nfs-common
sudo mkdir -p /mnt/synology_backup
sudo nano /etc/fstab            # add the line above
sudo systemctl daemon-reload
touch /mnt/synology_backup/test && ls -l /mnt/synology_backup && rm /mnt/synology_backup/test
```

### 3. Install the backup

```bash
sudo install -m 755 backup/mariadb-backup.sh /usr/local/bin/
sudo install -m 644 backup/mariadb-backup.service backup/mariadb-backup.timer /etc/systemd/system/
sudo install -m 600 backup/mariadb-backup.default /etc/default/mariadb-backup

# Run once by hand, then turn on the nightly timer
sudo systemctl daemon-reload
sudo systemctl start mariadb-backup.service
journalctl -u mariadb-backup -n 20 --no-pager
sudo systemctl enable --now mariadb-backup.timer
```

## Checking on it

```bash
systemctl list-timers mariadb-backup.timer     # next and last run
systemctl status mariadb-backup.service        # result of the last run
journalctl -u mariadb-backup --since -3d       # what it did
ls -lh /mnt/hdd/backups/mariadb/$(date +%F)    # today's files
```

## Restoring

Each file recreates its database (it contains `CREATE DATABASE` and `USE`).
Stop the app that uses it first:

```bash
sudo systemctl stop snmp-app
zcat /mnt/hdd/backups/mariadb/2026-10-25/snmp_db.sql.gz | sudo mariadb
sudo systemctl start snmp-app
```

Extra files are kept under their full path in `files/`. To put Wi-Fi
Control's saved secrets back (both files, always together):

```bash
B=/mnt/hdd/backups/mariadb/2026-10-25/files
sudo systemctl stop wifi-control
sudo install -m 600 -o myhomeservices -g myhomeservices \
  $B/home/myhomeservices/MyWifiControl/secrets.json \
  $B/home/myhomeservices/MyWifiControl/secret.key \
  /home/myhomeservices/MyWifiControl/
sudo systemctl start wifi-control
```

After a full rebuild of the server, restore the users and grants first:

```bash
zcat users-and-grants.sql.gz | sudo mariadb
```

To check a backup without touching the live data, restore it under another name:

```bash
zcat /mnt/hdd/backups/mariadb/2026-10-25/hub_db.sql.gz \
  | sed 's/`hub_db`/`hub_db_restore_test`/g' | sudo mariadb
sudo mariadb -e "SELECT username, role FROM hub_db_restore_test.users; DROP DATABASE hub_db_restore_test;"
```
