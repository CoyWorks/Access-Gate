# Backup and restore

Open **Backup & restore** in administration. Run `bash update.sh` once to install the maintenance worker before using this screen.

## Create a backup

1. Enter the current admin password.
2. Choose and confirm a separate backup passphrase of 12–256 characters.
3. Create the encrypted backup, refresh the job page and download the `.agbackup` file.
4. Store the archive and passphrase separately. A forgotten passphrase cannot be recovered.

The worker uses SQLite's backup API, including committed WAL contents. The authenticated AES-256-GCM archive uses scrypt with a random salt. It contains database state, configuration/pepper, the retained root CA and issuing/portal certificate keys. No unencrypted private-key archive is downloadable. The root worker serializes jobs; the web application remains unprivileged.

Backups are capped at 64 MiB and downloads expire after seven days. Job summaries remain for 30 days. These limits are explicit: this release is intended for the dedicated small-server installation. Root CLI configuration changes must not run concurrently with backup/restore. Copying an archive is not a source-code backup or a backup of external Pi-hole, firewall or device settings.

## Restore

1. Install a matching Access Gate schema version on the dedicated Ubuntu server at `10.40.22.5`. Use a working fresh install for replacement-host recovery. Install the same source release first; restore does not downgrade application code.
2. Upload the encrypted archive and enter its passphrase and the current server's admin password.
3. Wait for **Preflight passed**. Review the saved version/date/counts. Database integrity, schema, required components, configuration and certificate/key consistency are checked in private staging before live data is touched.
4. Within 15 minutes, enter the current password again and type `REVOKE` to confirm.
5. Services briefly stop. A root-only encrypted rollback snapshot is made, state is replaced, gateway settings are regenerated and service readiness is checked.
6. Sign in with the **admin password from the backup**. All restored administrator logins are invalidated. Check System status, DNS mappings, CA trust and the gateway from an actual device. Generate fresh codes.

**Every restored code, batch and grant is revoked, even when the archive describes it as unused.** Pending access requests expire. This prevents an old snapshot from resurrecting used/revoked access. Domain rules, exclusions, history and settings are retained. Restoring the original CA preserves trust on devices that already trusted that CA; moving from another CA may require installing the restored public CA. Restored management networks must allow your address; use `configure.py --reset-admin-networks` locally if needed.

On replacement failure the worker attempts rollback with the same fail-closed revocation policy. Check the maintenance result, `systemctl status access-gate-maintenance access-gate access-gate-gateway nginx` and the root journal. Encrypted rollback snapshots are retained under `/var/lib/access-gate/maintenance/*.rollback`, protected by the uploaded backup's passphrase; root should remove them when recovery is accepted. A hard power loss during replacement can require root recovery; the operation is not claimed to be filesystem-transactional. Jobs interrupted by worker restart are marked failed and never automatically replayed.

## Privilege boundary

`access-gate-maintenance.service` runs a fixed-action worker as root. It accepts only backup, preflight and confirmed restore jobs from a private inbox. The portal can write requests but cannot choose filesystem paths, shell commands, archive members or restore destinations. Inputs are bounded, archives are authenticated before parsing, uploaded tar/zip extraction is not used, and symlink files are refused. Secrets are removed from the inbox after processing; the decrypted preview passphrase is root-only and expires after 15 minutes. Job results contain summaries only. The application service remains `accessgate` with no sudo.

## Verified recovery exercise

Automated synthetic-server tests exercise committed WAL backup, authenticated encryption, wrong-password/corruption/schema refusal, preview without replacement, full restore and post-restore revocation, readiness failure/rollback, duplicate jobs, symlink/path refusal and admin/CSRF/password controls. The exercise uses temporary certificate/database state and mocked service commands; final service/route/CA acceptance on the real server remains an operator check.
