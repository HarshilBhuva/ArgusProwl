# ArgusProwl Backup and Disaster Recovery Operations

This runbook describes an encrypted, off-host backup profile for the supported single-instance SQLite deployment. It uses [restic](https://restic.net/) rather than implementing cryptography or an object-store protocol inside ArgusProwl. Restic encrypts repository data client-side and supports AWS S3 and S3-compatible endpoints.

## Scope and guarantees

- The application is stopped while a backup set is created, so the evidence, alert, audit/security, and enabled auxiliary SQLite files are captured behind one operator-controlled maintenance barrier.
- ArgusProwl verifies every SQLite database and its manifests before restic receives the generation.
- Restic encrypts content before upload. The repository password and S3 credentials are supplied independently of the backup data.
- The runner verifies repository structure, reads a configurable sample of repository data, and lists the exact new snapshot before applying retention.
- The runner records last success/failure state in `backup-status.json` under the protected local backup directory.
- Remote retention defaults to 2 latest, 7 daily, 4 weekly, and 12 monthly snapshots. Restic retention groups by host (not the timestamped source path), so successive generations are pruned together. Use a distinct `RESTIC_HOST` for each installation sharing a repository. After the remote snapshot passes verification and retention succeeds, the runner verifies local generations and keeps the newest `ARGUSPROWL_LOCAL_KEEP` (minimum 2); unverified local generations are retained rather than deleted.
- This profile does not establish an RPO/RTO. Publish targets only after measuring backup duration, restore duration, data volume, and host-loss recovery in the target environment.

## Install and initialize the remote repository

Install a current, supported restic release from its official distribution channel. Do not install a binary from an untrusted mirror.

Create an S3 bucket/prefix with private access and versioning controls appropriate to the organization's retention policy. Object-lock policies can prevent restic pruning; enable them only when their immutability period is deliberately aligned with the backup retention design. Use a dedicated least-privilege credential restricted to that repository prefix.

Create the password file outside the application data and backup directories:

```bash
sudo install -d -m 0700 /etc/argusprowl
sudo sh -c 'umask 077; printf "%s" "REPLACE-WITH-A-LONG-RANDOM-PASSPHRASE" > /etc/argusprowl/restic-password'
sudo chmod 0600 /etc/argusprowl/restic-password
```

Store an independent recovery copy of this password in the organization's secret manager or offline recovery vault. If the password is lost, restic cannot decrypt the repository. Never upload the password file to the same bucket.

Create `/etc/argusprowl/backup.env` with mode 0600:

```bash
ARGUSPROWL_CONFIG=/etc/argusprowl/config.yaml
ARGUSPROWL_BACKUP_ROOT=/var/lib/argusprowl/backups
ARGUSPROWL_PYTHON=/opt/argusprowl/.venv/bin/python
RESTIC_REPOSITORY=s3:https://s3.example.com/argusprowl-backups/production
RESTIC_PASSWORD_FILE=/etc/argusprowl/restic-password
RESTIC_CACHE_DIR=/var/cache/argusprowl/restic
RESTIC_HOST=argusprowl-production-01
AWS_ACCESS_KEY_ID=REPLACE_WITH_DEDICATED_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=REPLACE_WITH_DEDICATED_SECRET_KEY
AWS_DEFAULT_REGION=us-east-1
RESTIC_CHECK_DATA_PERCENT=5
ARGUSPROWL_LOCAL_KEEP=2
```

For AWS S3, use the appropriate regional endpoint and least-privilege IAM credentials. For another S3-compatible provider, use its documented HTTPS endpoint and credentials. Do not put credentials in the repository URL or command-line arguments.

Initialize the repository exactly once:

```bash
sudo bash -c 'set -a; source /etc/argusprowl/backup.env; set +a; restic init'
```

Do not configure the runner to initialize an absent repository automatically: a typo in the repository URL must fail, not create a new empty backup destination.

## Install the runner and schedule

Install the runner and unit files:

```bash
sudo install -d -m 0700 /var/lib/argusprowl/backups /var/cache/argusprowl/restic
sudo install -m 0750 scripts/argusprowl-backup-restic.sh /usr/local/libexec/argusprowl-backup-restic.sh
sudo install -m 0644 deploy/systemd/argusprowl-backup.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/argusprowl-backup.timer /etc/systemd/system/
sudo chmod 0600 /etc/argusprowl/backup.env /etc/argusprowl/restic-password
sudo install -d -m 0700 /var/lib/argusprowl/backups /var/cache/argusprowl/restic
sudo systemctl daemon-reload
```

The supplied systemd service records whether `argusprowl.service` was active, stops it for the backup, and restarts it through `ExecStopPost` only if it was active before maintenance. The restart hook runs after success and failure. If your application unit has another name, change both systemctl commands before enabling the timer. Set a unique `RESTIC_HOST` for every installation sharing a repository; the retention policy groups by this value. The service runs as root to manage the application unit and read the protected configuration/SQLite files. The unit's working directory is `/var/lib/argusprowl`; use absolute database paths under `/var/lib/argusprowl/data` in the production YAML (including audit/alert/auxiliary stores) so the application and backup service resolve the same files. Review `ReadWritePaths` and adapt them to every configured database and backup path; do not broaden them unnecessarily.

Run one manual backup and verify the resulting status before enabling the schedule:

```bash
sudo systemctl start argusprowl-backup.service
sudo cat /var/lib/argusprowl/backups/backup-status.json
sudo systemctl status argusprowl-backup.service
```

Enable the daily timer:

```bash
sudo systemctl enable --now argusprowl-backup.timer
systemctl list-timers argusprowl-backup.timer
journalctl -u argusprowl-backup.service
```

The timer runs daily at 02:15 local system time with a randomized delay and catches up after downtime. The app is unavailable during the backup window. Size the window and choose the schedule based on measured data volume and service availability requirements.

## Verify and inspect

```bash
sudo bash -c 'set -a; source /etc/argusprowl/backup.env; set +a; restic snapshots --tag argusprowl --host "$RESTIC_HOST"'
sudo bash -c 'set -a; source /etc/argusprowl/backup.env; set +a; restic check --read-data'
sudo cat /var/lib/argusprowl/backups/backup-status.json
```

The scheduled runner checks 5% of repository data by default on each run; increase `RESTIC_CHECK_DATA_PERCENT` for deeper verification at the cost of runtime and object-store reads. Periodically run a full `restic check --read-data` during a maintenance window.

## Disaster recovery drill

Perform this drill on a separate host or isolated restore environment. Do not overwrite the production data directory during a test.

1. Install the same ArgusProwl release and a compatible restic version on the recovery host.
2. Provide the S3 repository URL, AWS/S3 credentials, and the independently recovered restic password file.
3. List snapshots and restore the latest tagged generation to an isolated directory:

   ```bash
   restic snapshots --tag argusprowl --host "$RESTIC_HOST"
   restic restore latest --tag argusprowl --host "$RESTIC_HOST" --target /srv/argusprowl-restore
   ```

4. Locate the restored `backup-set.json` in the restic restore output.
5. Use ArgusProwl's isolated set-restore command to verify and restore every member without touching production data:

   ```bash
   python -m argusprowl backup set-verify <generation-directory>
   python -m argusprowl backup set-restore <generation-directory> \
     --output-dir /srv/argusprowl-restore/sqlite
   ```

6. Create a recovery YAML from the production configuration and point `storage.database_path`, `api.audit_db_path` (when the API is enabled), `alert_persistence.db_path`, and any enabled behavior/annotation database paths at their matching restored files (`evidence.db`, `audit.db`, `alerts.db`, `behavior.db`, `annotations.db`). Keep the recovery directory isolated.
7. Start the application against that recovery YAML, run health checks, and verify evidence provenance, alerts, audit-chain integrity, and credential/session revocation state using the restore-drill acceptance test.
8. Record backup age, time to retrieve, time to verify, time to restore, application recovery time, and any missing state. Repeat after application upgrades and periodically thereafter.

A green backup job is not a successful disaster-recovery drill. The acceptance test must restore data and start the application in an isolated environment.

## Operations and failure handling

- A non-zero runner exit records `state=failed`, `last_failure_at`, and an error summary. A successful run records `last_success_at` and the exact restic snapshot ID.
- Alert on a stale `last_success_at`, any `state=failed`, missing status file, low free space, or a backup duration that exceeds the maintenance window.
- Keep the local backup root on a persistent, access-controlled volume. It contains plaintext SQLite backup sets; restrict it to the backup administrator and protect the host.
- The restic password must be recoverable independently of the S3 repository. Test key recovery, not just key presence.
- Local cleanup runs only after a successful remote backup, repository/data verification, exact-snapshot listing, and restic retention. The default keeps two complete local generations; set `ARGUSPROWL_LOCAL_KEEP` to a larger value when required. Unverified local generations are never automatically deleted. Monitor disk capacity.
- Restic retention runs only after backup, repository checks, and exact-snapshot listing succeed. It keeps at least two recent snapshots plus the configured daily/weekly/monthly generations.
- S3 credentials should be dedicated and scoped to the repository prefix. Rotate credentials using the provider's supported overlap procedure.
- The backup set is not a cross-database transaction. The app is stopped to establish a coordinated maintenance point; `--confirm-offline` remains an operator attestation.
