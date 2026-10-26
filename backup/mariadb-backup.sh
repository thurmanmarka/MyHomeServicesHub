#!/bin/bash
# Nightly MariaDB backup for the home services Pi.
#
# Dumps every application database (plus MariaDB users and grants) into
# $BACKUP_DIR/YYYY-MM-DD/, keeps the newest $KEEP_DAYS days, then mirrors the
# folder to the NAS's NFS share. Settings come from /etc/default/mariadb-backup.
# Runs as root so it can use MariaDB's unix_socket login (no password needed).
set -euo pipefail

[ -f /etc/default/mariadb-backup ] && . /etc/default/mariadb-backup
: "${BACKUP_DIR:=/mnt/hdd/backups/mariadb}"
: "${REQUIRE_MOUNT:=/mnt/hdd}"
: "${KEEP_DAYS:=14}"
: "${NAS_MOUNT:=}"  # e.g. /mnt/synology_backup (the NFS mount point); empty = keep local copies only
: "${NAS_DIR:=}"    # folder inside it to copy to; often the same as NAS_MOUNT
# A normal night deletes one dated folder (a handful of files) on the NAS.
# More than this means the local folder was emptied, so stop rather than
# mirror that deletion to the NAS.
: "${MAX_NAS_DELETES:=20}"
# Extra files to include, separated by spaces (paths without spaces)
: "${EXTRA_FILES:=}"

fail() { echo "BACKUP FAILED: $*" >&2; exit 1; }

# Never write into the empty mount point on the SD card
mountpoint -q "$REQUIRE_MOUNT" || fail "$REQUIRE_MOUNT is not mounted"

umask 077
day=$(date +%F)
tmp="$BACKUP_DIR/.tmp-$day"
dest="$BACKUP_DIR/$day"
mkdir -p "$BACKUP_DIR"
rm -rf "$tmp"
mkdir "$tmp"
# Don't leave a half-written dump behind if anything fails
trap 'rm -rf "$tmp"' EXIT

dbs=$(mariadb -N -e "SELECT schema_name FROM information_schema.schemata
    WHERE schema_name NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
    ORDER BY schema_name")
[ -n "$dbs" ] || fail "no databases found"

for db in $dbs; do
    mariadb-dump --single-transaction --routines --triggers --events --databases "$db" \
        | gzip > "$tmp/$db.sql.gz" || fail "dump of $db failed"
    # mariadb-dump ends a complete dump with this line; a missing one means it was cut short
    zcat "$tmp/$db.sql.gz" | tail -n 1 | grep -q '^-- Dump completed' \
        || fail "dump of $db is incomplete"
done

# Database users and their grants, so a rebuilt server can be restored fully
mariadb-dump --system=users | gzip > "$tmp/users-and-grants.sql.gz" \
    || fail "dump of users and grants failed"

# Files that aren't in a database (e.g. Wi-Fi Control's saved secrets), kept
# under their full path in files/. A missing file is reported, not fatal:
# some only appear once the app has saved something.
for f in $EXTRA_FILES; do
    if [ -f "$f" ]; then
        mkdir -p "$tmp/files"
        cp --parents --preserve=mode,timestamps "$f" "$tmp/files/" || fail "copy of $f failed"
    else
        echo "Skipped $f (not found)"
    fi
done

# Swap the finished dump into place only once every file is good
rm -rf "$dest"
mv "$tmp" "$dest"
echo "Saved $(echo $dbs | wc -w) database(s) to $dest ($(du -sh "$dest" | cut -f1))"

# Keep the newest $KEEP_DAYS dated folders (today counts as one)
cutoff=$(date -d "-$((KEEP_DAYS - 1)) days" +%F)
for dir in "$BACKUP_DIR"/20??-??-??; do
    [ -d "$dir" ] || continue
    if [[ "$(basename "$dir")" < "$cutoff" ]]; then
        rm -rf "$dir"
        echo "Removed old backup $(basename "$dir")"
    fi
done

if [ -z "$NAS_MOUNT" ]; then
    echo "No NAS_MOUNT set; backups are on this machine only"
    exit 0
fi

# Touch the mount point first so an automount gets mounted, then make sure it
# really is the NFS share; otherwise the copy would land on the SD card.
ls "$NAS_MOUNT" > /dev/null 2>&1 || true
findmnt -n -t nfs,nfs4 --mountpoint "$NAS_MOUNT" > /dev/null \
    || fail "NAS share is not mounted at $NAS_MOUNT (local backup in $dest is fine)"

mkdir -p "$NAS_DIR"
# -rlpt rather than -a: the NAS may not let root set file owners over NFS
rsync -rlpt --delete --max-delete="$MAX_NAS_DELETES" --exclude '.tmp-*' \
    "$BACKUP_DIR/" "$NAS_DIR/" \
    || fail "copy to $NAS_DIR failed (local backup in $dest is fine)"
echo "Copied to $NAS_DIR"
