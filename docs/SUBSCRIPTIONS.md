# Reviewed blocklist subscriptions

Open **Restricted domains → Blocklist subscriptions**. One-time URL imports stay manual and additive; they are never silently converted into subscriptions. On a remote gateway, manage subscriptions on its authority, which exports the resulting global rules.

1. Add a name, public HTTPS raw-list URL, exact/subdomain scope and hourly/six-hourly/daily interval.
2. The source is downloaded and parsed with the existing public-address validation, pinned verified HTTPS connection, redirect checks and 32 MiB/500,000-domain limits. Review unique count, additions, removals, skipped entries, duplicates and scope. Download the full pending domain snapshot if needed; the page displays the first 20 additions/removals.
3. Approve that specific snapshot. A stale approval cannot apply a different revision. Until this first approval nothing is enabled.
4. Scheduled refresh runs in a single bounded background thread of the existing unprivileged scheduler, independently of code-generation scheduling. It handles one due source at a time; database leases prevent duplicate fetches and expire after 120 seconds if a process dies. The scheduler checks every 15 seconds. Only activated, unpaused sources without a pending review are eligible.

Later scheduled changes apply automatically only when removals are at most 20% of the current source count, additions plus removals at most 25%, and total changes at most 10,000 domains. Anything larger waits for review with the last applied snapshot active. Manual Fetch for review always stages changes for approval. Empty, malformed, oversized, private-address or unreachable responses fail without changing effective rules; failures retry after at most 15 minutes. Unchanged successful polls update health without replacing the meaningful rollback point.

## Ownership and scope

Schema 12 migrates every existing rule, including previous one-time imports, disabled entries and exact scopes, as manual ownership. Re-running initialization does not claim source-only rules as manual. A domain remains while it is owned manually or by any applied source. Source duplicates combine with subdomain scope if any owning source includes subdomains.

A manual rule overrides source enabled/scope state **for the same hostname**. Explicitly adding an already-listed source domain also claims it manually, retaining its current state/scope. Disabling or changing scope creates a manual override. Deleting a source-owned rule creates a suppression so a later refresh cannot restore it; explicitly adding it again removes that suppression. These are ownership decisions, not negative DNS exceptions: another enabled parent suffix rule can still cover a manually disabled/deleted child. Use the policy explanation to inspect the actual match.

A source refresh never deletes manual ownership or another source's membership. The complete effective domain table is materialized in one SQLite transaction; gateway exports, DNS publisher and Pi-hole feeds cannot observe a half-applied list. The combined effective list remains limited to 500,000 domains. An over-limit application rolls back and retains its pending review.

## Pause, rollback and remove

- **Pause** stops refreshes and invalidates any in-flight fetch lease. Applied mappings remain active.
- **Discard pending** keeps the currently applied set and removes only the proposal.
- **Roll back** restores the previous applied membership, recomputes overlaps/manual overrides atomically and pauses updates, so a subsequent poll cannot immediately undo the rollback.
- **Remove** deletes this source's ownership and snapshots. Manual rules and other sources remain. As with any removal, inspect policy for domains that become unrestricted.

At most ten sources are supported. Each retains at most three membership snapshots: current, previous and pending. Successful fetch time, state, pending revision and warnings are visible in the portal; source failures are not presented as healthy. Existing encrypted backup size limits still apply to the database including snapshots. Backups from a different schema require the matching application version before restoring, as in the existing recovery workflow.

The built-in DNS publisher normally picks up committed changes within a few seconds. Pi-hole must fetch and apply `/pihole.conf` as before. This feature does not change access-profile behavior or cache session authorization.
