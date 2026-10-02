#!/usr/bin/env python3
"""Decrypt only the forensically relevant part of an encrypted iOS backup.

`mvt-ios decrypt-backup` decrypts every file, which doubles disk usage.
Photos, videos and voice notes are irrelevant to MVT's modules, so this
skips them. The output keeps MVT's layout (Manifest.db, root plists,
XX/<fileID>), so `mvt-ios check-backup` reads it as a normal decrypted
backup; MVT already tolerates files missing from a partial backup.

The password is read interactively (or from MVT_IOS_BACKUP_PASSWORD) and is
never written to disk or logs. Uses iphone_backup_decrypt (MIT) directly, so no
MVT code runs in this process; MVT itself is only invoked as a separate program.

Usage: python app/helpers/partial_decrypt.py <encrypted_backup_dir> <output_dir>
Exit codes: 0 ok, 1 some files failed, 2 wrong password.
"""
import argparse
import getpass
import os
import shutil
import sys
from pathlib import Path

from iphone_backup_decrypt import EncryptedBackup
from iphone_backup_decrypt.utils import FilePlist

SKIP_DOMAINS = {"CameraRollDomain"}
MEDIA_EXTENSIONS = {
    ".jpg", ".jpeg", ".heic", ".heif", ".png", ".gif", ".webp", ".tif", ".tiff",
    ".mov", ".mp4", ".m4v", ".3gp", ".avi",
    ".m4a", ".mp3", ".aac", ".caf", ".opus", ".amr", ".wav", ".aiff",
}
DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".sqlitedb", ".plist", ".storedata"}
MAX_NON_DB_BYTES = 100 * 1024 * 1024


def wanted(domain: str, relative_path: str, size: int) -> bool:
    if domain in SKIP_DOMAINS:
        return False
    name = relative_path.lower()
    # WAL/SHM sidecars carry uncommitted rows that MVT needs
    base = name.removesuffix("-wal").removesuffix("-shm")
    suffix = Path(base).suffix
    if suffix in MEDIA_EXTENSIONS:
        return False
    if size > MAX_NON_DB_BYTES and suffix not in DATABASE_EXTENSIONS:
        return False
    return True


def extract(backup, file_id, file_bplist, output):
    """Decrypt one manifest entry straight to disk (large files never sit in memory)."""
    plist = FilePlist(file_bplist)
    source = Path(backup._backup_directory, file_id[:2], file_id)
    if plist.encryption_key is None:  # stored unencrypted
        shutil.copy2(source, output)
        return
    backup._read_and_unlock_keybag()
    key = backup._keybag.unwrapKeyForClass(plist.protection_class, plist.encryption_key)
    backup._decrypt_file_to_disk(file_id=file_id, key=key, file_plist=plist, output_filepath=str(output))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("backup_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    backup_root = args.backup_dir.resolve()
    if not (backup_root / "Manifest.plist").exists():
        candidates = list(backup_root.glob("*/Manifest.plist"))
        if len(candidates) != 1:
            sys.exit(f"Expected one backup in {backup_root}, found {len(candidates)}")
        backup_root = candidates[0].parent
    dest_root = args.output_dir.resolve()
    dest_root.mkdir(parents=True, exist_ok=True)

    password = os.environ.get("MVT_IOS_BACKUP_PASSWORD") or getpass.getpass("Backup password: ")
    backup = EncryptedBackup(backup_directory=str(backup_root), passphrase=password)
    del password
    try:
        backup.test_decryption()
    except Exception as exc:
        print(f"WRONG_PASSWORD: could not unlock the backup: {exc}", file=sys.stderr)
        return 2
    print("Backup unlocked.")

    backup.save_manifest_file(output_filename=str(dest_root / "Manifest.db"))
    for plist in backup_root.glob("*.plist"):
        shutil.copy(plist, dest_root)

    kept = skipped = failed = 0
    kept_bytes = skipped_bytes = 0
    with backup.manifest_db_cursor() as cur:
        cur.execute("SELECT fileID, domain, relativePath, file FROM Files WHERE flags=1")
        for file_id, domain, relative_path, file_bplist in cur.fetchall():
            source = backup_root / file_id[:2] / file_id
            if not source.exists():
                continue
            size = FilePlist(file_bplist).filesize or 0
            if not wanted(domain, relative_path, size):
                skipped += 1
                skipped_bytes += size
                continue
            output = dest_root / file_id[:2] / file_id
            output.parent.mkdir(parents=True, exist_ok=True)
            try:
                extract(backup, file_id, file_bplist, output)
                kept += 1
                kept_bytes += size
            except Exception as exc:
                failed += 1
                print(f"Failed: {domain}/{relative_path}: {exc}", file=sys.stderr)
            if (kept + failed) % 2000 == 0:
                print(f"  {kept} files decrypted ({kept_bytes / 1e9:.1f} GB)...")

    print(
        f"Done: {kept} files decrypted ({kept_bytes / 1e9:.2f} GB), "
        f"{skipped} media/large files skipped ({skipped_bytes / 1e9:.2f} GB), {failed} failed."
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
