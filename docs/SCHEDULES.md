# Recurring code batches

Open **Schedules → Create schedule**. Choose a name, daily/weekly recurrence, weekday, local time and Europe/Amsterdam or UTC. Set code count, activation validity and access duration using the same limits as manual batches. Confirm the current admin password and choose a separate export passphrase (12–256 characters).

The schedule is enabled on creation. Its detail page previews the next three local runs, shows the last outcome and latest 100 runs, and offers **Pause**, **Resume** and **Run now**. Run now works while paused, creates one extra batch and does not shift the next scheduled occurrence. Reposting the same Run now form is idempotent; refreshing the detail page deliberately creates a new form. To change settings or the export passphrase, pause the old schedule and create a replacement. Profiles remain future work (#11); scheduled codes currently grant the global restricted-domain scope.

## Secure collection

The scheduler has only the schedule's public encryption key. Generated full codes are encrypted using ephemeral X25519, HKDF-SHA256 and AES-256-GCM. The private key is encrypted with the separate passphrase using scrypt/AES-GCM; the passphrase is never stored. Ordinary code records remain keyed hashes.

A ready run offers **Collect codes once**, requiring the current admin password and that schedule's export passphrase. Choose text, printable cards or PDF, optionally QR. Successful collection deletes the encrypted output transactionally and returns full codes once. Save the output before navigating away. Wrong passwords leave the output intact; concurrent collectors cannot both retrieve it. Rendering failures use the same text fallback as manual generation. A lost response after successful collection cannot be recovered: revoke that batch and use Run now if necessary.

Uncollected output expires at the earlier of seven days or its activation deadline. The worker removes its encrypted payload and revokes the uncollected batch. A forgotten export passphrase cannot be recovered; pause the schedule, revoke uncollected batches and create a replacement. No outbound email/webhook delivery is enabled. This explicit portal collection is the chosen secure delivery method.

## Timing and failures

- A dedicated **unprivileged** `access-gate-scheduler.service` checks every 15 seconds. SQLite write transactions and unique schedule/occurrence keys prevent duplicate batches across workers, retries and restart.
- Code validity begins at actual generation time, matching manual generation. It does not begin at an earlier missed scheduled time.
- A nonexistent local time during the spring clock change is skipped. A repeated autumn local time runs once, at its first occurrence (fold 0).
- After downtime only the latest due occurrence is generated, and only if it is at most 24 hours old. Older missed occurrences are skipped; no backlog of batches is generated. Resume skips paused occurrences and calculates a future run.
- Generation/encryption errors roll back both batch and output, record a failed run and wait until the next occurrence. Use Run now to deliberately retry. Raw errors/secrets are not logged as run outcomes.
- A backwards clock jump does not reissue a completed occurrence. Check clock synchronization in System status.
- Restore disables restored schedules and invalidates uncollected outputs, in addition to revoking all restored codes/grants. Review schedules and explicitly resume them after recovery.

Run the normal updater to install the service and schema 9 migration. Existing codes, CA, grants and settings are retained. Backups created with the earlier schema require the matching installed release for initial restore, followed by the normal update. Root checks: `systemctl status access-gate-scheduler` and `journalctl -u access-gate-scheduler --no-pager`. The System status page includes the scheduler and maintenance worker.

Tests cover DST, weekly/daily recurrence, missed runs, pause/resume, concurrent workers and collectors, restart persistence, correct code durations, encrypted output, expiry/revocation and generation failure with no duplicate batch. Tests use temporary SQLite data; enabling the new service on the target server is performed by `bash update.sh`.
