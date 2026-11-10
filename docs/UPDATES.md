# Updates from administration

Run the normal `bash update.sh` once to install version 0.13 or later. This installs the fixed-action maintenance worker and records the actual deployed version/commit. From then on, open **Updates** in administration.

1. **Check for updates** queues a bounded Git check against `https://github.com/CoyWorks/Access-Gate.git`, branch `main`.
2. Open the resulting job. Review installed version/commit, available version/commit and the recent commit summary.
3. Enter the current admin password and type `UPDATE`. Confirmation is valid for 15 minutes and can start only one installation.
4. Watch the saved progress. The portal and restricted browsing briefly disconnect while the normal installer replaces code/templates/static files and restarts services. Status polling resumes after the portal returns. If your login expired, sign in again and reopen Updates or the saved job URL.
5. A successful job reports the installed identity, HTTPS readiness and the installer's root-only snapshot location. Check System status and a real restricted website afterwards.

The displayed installed version comes from `/opt/access-gate/VERSION`, not the source checkout. `/etc/access-gate/deployment.json` records the commit only after a successful install/readiness check and only for a clean Git source. Archive/older/modified installations show an unknown commit until a clean deployment establishes it. Fetching a source tree never changes the reported installed version.

## Safety and privilege boundary

The portal remains unprivileged and has no sudo. A root worker accepts only fixed action names and reviewed job identifiers; web requests cannot choose a command, branch, remote URL, source path or log path. The worker uses its own protected clone at `/opt/access-gate-update-src`, separate from your normal CLI clone. Git hooks and fsmonitor are disabled, file-protocol remotes are disallowed, origin must match the fixed public repository, and clone/parents must be protected and root-owned.

The update follows the existing CLI workflow: a clean `main` branch, fetch, fast-forward ancestry checks and the newly downloaded `update.sh --local`/`install.sh update`. Dirty/untracked source, divergent source or installed history, wrong origin/branch, older versions, failed fetches and changed remote commits stop before installation. The remote commit is checked again after confirmation; a newly published commit requires another review. No force reset or automatic history repair is performed.

The root worker and CLI installer share one advisory maintenance lock. Only one backup/restore/update/install runs at a time. Duplicate confirmations cannot start a second deployment, and an interrupted job is marked failed rather than automatically replayed. Job state lives outside replaced application files. The worker reloads its code after deployment; worker-initiated installation does not stop its own process mid-job. The CLI updater still works independently and retains the same install/resume/update behavior.

## Failures and recovery

- Before deployment, Git failures leave installed application/state untouched.
- The normal installer stops portal/gateway/scheduler, retains a root-only `access-gate-resume.*` snapshot and previous application directory, preserves codes/configuration/CA, then validates services and HTTPS readiness.
- Installer or final health failure is shown as failed; there is no automatic schema downgrade. Check actual installed files and System status. A stale deployment marker is not treated as a verified new commit.
- Root logs are `/var/lib/access-gate/maintenance/JOB_ID.update.log`. They are never downloadable in the portal. Job summaries exclude raw stdout, credentials and secrets. Git failures can be investigated with the root-only clone and normal Git commands.
- If the portal cannot return, inspect `systemctl status access-gate-maintenance access-gate access-gate-gateway access-gate-scheduler nginx` and the root log. Fix the reported problem and rerun the normal CLI updater. Do not reset the installation to repair an update.
- For data recovery use the encrypted [backup/restore workflow](RECOVERY.md), with a matching application/schema version and explicit code invalidation. Saved installer snapshots/previous source are recovery aids, not a promised automatic rollback across schema changes.

Git commands have finite timeouts (normally 120 seconds); installation has a 30-minute limit. Local readiness is checked again after installation. Root logs and installer snapshots are retained for deliberate cleanup by root. Job summaries expire after 30 days; review confirmations expire after 15 minutes. Activity records requested checks/installs and worker outcomes, subject to configured activity retention and database availability.

## Verification

Tests mock the privileged deployment boundary and cover source/installed identity separation, success, dirty/diverged/wrong-remote/branch/downgrade refusal, network failure, stale/changed/expired previews, one-time confirmation, installer failure, persistent results across portal recreation, safe error summaries and admin/password/CSRF checks. Client tests cover progress refresh, restart disconnection, text-only rendering and terminal-state reload. No live server update is claimed by these local tests.
