# File areas

File areas are the BBS's download library. Each area lives on disk
under a configurable storage path.

## Creating an area

**Admin → File Areas → Add Area**:

| field               | purpose                                          |
| ------------------- | ------------------------------------------------ |
| `tag`               | unique key (e.g. `FILES.GAMES`)                  |
| `name`              | display name                                     |
| `description`       | shown in the area listing                        |
| `storage_path`      | absolute path on disk where files live           |
| `category`          | which category this area belongs to (see below)  |
| `upload_permission` | `none` / `users` / `sysop`                       |
| `is_sysop_only`     | hide entirely from non-admins                    |
| `password`          | optional — area lock                             |
| `min_access_level`  | minimum access level to see/browse the area (default 10 = registered users; 0 = everyone, 50 = VIP, 100 = sysop) |
| `min_write_level`   | minimum access level to upload, independent of `upload_permission` |

## Categories and submenu sections

Every file area belongs to a category (**Admin → File Areas →
Categories**), shown as a header on the area list (terminal and web).
By default a category's areas are listed inline under its header —
fine for a handful of areas, but once a category grows large it can
run off the bottom of a real terminal screen.

Flip **"Show as a submenu section"** on a category to collapse it
instead: the top-level file-area list shows one selectable line for
that whole category (e.g. "Games → (12 areas)"), and picking it opens
a second screen listing just that category's own areas, with `B`/`Q`
(terminal) or the browser back button (web) returning to the parent
list. One level deep only. Off by default; existing categories/
installs render exactly as before until a sysop opts one in. Reorder
categories (and individual areas within a category) by drag-and-drop
in the web admin, or with the up/down keys in the `anetbbs-cfg`
terminal tool — see [`28-anetbbs-cfg.md`](28-anetbbs-cfg.md).

A submenu category's own position in the top-level list is controlled
by its own Sort Order (set on the category itself), not by any member
area's number — matches Door Games' own submenu category behavior
(see [`14-door-games.md`](14-door-games.md#categories-and-submenu-sections)).
Numbering collisions (most commonly a bulk-imported network that never
set individual numbers) resolve themselves automatically on the next
restart.

## Where files live

Each area stores binaries in its `storage_path`. Sysop can drop files
in directly (e.g. via SFTP) or users can upload via the web or FTP.

Migrating an existing file collection that already has a classic
`FILES.BBS` / `FILES.BSS` index? `tools/bbs-files-tool.py` builds the
`.descriptions.json` cache ANetBBS reads for an area directly from
that index, without touching the original file. See
[`FILEBASE-MIGRATION.md`](FILEBASE-MIGRATION.md) for the full
walkthrough.

## FTP access

When `FTP_ENABLED=true` in `.env` (or via **Admin → Settings**), the
ANetBBS FTP server lists permitted `FileArea` directories at the top
level. Each directory name includes the area ID and the URL-encoded tag.
Update saved FTP paths after upgrading. Three views use the same port:

- **Anonymous** (`anonymous` / blank password) — read-only, sees only
  active areas with public access level and `is_sysop_only=false`. Earns you the FTN nodelist
  `IFC` flag once advertised.
- **Authenticated users** — same login as web / telnet / SSH. An area's
  access level governs listing and download. Its upload permission and
  write level govern uploads. Use the web form for password-protected
  areas. Users can rename or delete their own FTP uploads recorded after
  the upgrade.
- **Sysop** — can read and manage files in active areas, including
  `is_sysop_only` areas. An area's upload permission still applies.

The server checks permissions before receiving a file, scans it in a
private staging directory and publishes it without replacing any
existing file. Use a new filename when the requested name already exists.
Start failed uploads again from the beginning. FTP downloads still support
resume. Uploads use `UPLOAD_MAX_SIZE` per file, `FTP_SESSION_UPLOAD_MAX_BYTES`
per session and `FTP_DAILY_UPLOAD_MAX_BYTES` per account per UTC day.
The daily counter resets when the FTP service restarts. Transfers pause
with an error if they would cross `FTP_MIN_FREE_BYTES`.

Ports to open on the firewall: `21/tcp` (control) and the configured
`FTP_PASV_PORTS` range (default `40000-40050`, data channels). See
`docs/PORTS.md` for the full table. Optional FTPS by setting
`FTP_TLS_CERTFILE` + `FTP_TLS_KEYFILE` (reuse your nginx
Let's Encrypt cert).

## Daily download quota

**Admin → File System → Download Quotas** (`/admin/file-quotas`) caps
how much a user can download per day, scaled by access level — so one
user can't tag-leech the whole file base overnight.

Configure a list of `(minimum access level, daily quota in MB)` tiers.
A user gets whichever tier has the **highest** access level they still
qualify for — e.g. tiers at level 50 and 100 give a level-75 user the
level-50 quota, not the level-100 one. A level with no tier configured
at or below it downloads unlimited. Admins always bypass.

Enforced everywhere a file can be downloaded: the web file-area and
file-gallery routes, ANSI telnet/SSH (Zmodem/Ymodem/Xmodem, single and
batch), PETSCII (Xmodem), and FTP (`RETR`) — anonymous FTP logins and
QWK-node FTP sessions are exempt (no local account to attribute usage
to, or out of scope respectively). Usage resets at Eastern midnight.

## Upload moderation queue

Set `FILE_MOD_QUEUE_ENABLED=true` in `.env` to require sysop approval
for non-admin uploads.

When on:
- User uploads → file lands in `data/file-queue/`, a
  `FileQueueEntry` row marks it pending.
- **Admin → File Queue** (`/admin/file-queue/`) lets sysop approve
  (moves to area `storage_path`) or reject (deletes).

## Upload safety checks

Two checks run automatically on every upload, before it's accepted:

- **Archive integrity test** — ZIP and TAR are checked directly. On Linux,
  7z, RAR and LHA inspection and automatic description extraction require
  `bsdtar` and `prlimit` (the `libarchive-tools` and `util-linux` packages on
  Debian). The decoder has memory, CPU, output and elapsed-time limits.
  When either tool is unavailable, these formats can still be uploaded
  and downloaded without automatic inspection or descriptions.
- **Content-hash dedup check** — a SHA-256 hash of the file's content
  (not its filename) is compared against everything already in the
  file base. A near-identical re-upload under a different name gets
  flagged instead of silently duplicating storage.

## File ratios

Mystic/Synchronet-style ratio control:

```
RATIO_MIN=0.05    # require uploads to be at least 5% of downloads
```

When set:
- Each download bumps `bytes_downloaded` on `FileRatio` per user.
- Each upload bumps `bytes_uploaded`.
- A new download is **blocked** if the user's projected ratio
  (after the download) is below `RATIO_MIN`. Sysops always exempt.

Set `RATIO_MIN=0` (default) to disable.

## Hatched files (TIC)

TIC ("Ticket File") is FidoNet's file-echo distribution mechanism —
the file-area equivalent of echomail. It runs in both directions:

### Inbound

If you've subscribed to file echos via FidoNet, the TIC processor
(`anetbbs/echomail/tic.py`) auto-files incoming `.tic` packets into the
matching area. Audit at **Admin → TIC In Log** (`/admin/tic-log`) — its
outbound counterpart, **TIC Out Log** (`/admin/hatch-log`), covers the
queue described below.

### Outbound — automatic, no manual step

This is the part that's easy to miss: **uploading a file to any file
area that has a network attached (`network_id` is not `None`) queues
that file for outbound distribution to every peer subscribed to that
file echo — automatically, with no extra action.** This includes all
9 of the bundled `ANN.FILES.*` areas (see [doc 6 —
Echomail](06-echomail.md) for the full list) as well as any custom
file-echo area you attach to a network yourself.

Concretely: `_hatch_if_network_area()` in `anetbbs/web/file_areas.py`
runs after every successful upload — the regular **Upload** form, the
sysop's **Manage → Upload**, and **Smart Upload** all call it, as does
the moderation queue's **Approve** action in
`anetbbs/web/file_queue.py` (so a queued upload only hatches out once
a sysop actually approves it, not the moment a user submits it). It
calls `hatch_local_file()` in `tic.py`, which queues one `HatchQueue`
row per subscribed peer (`FileEchoSubscription`) with a fresh CRC32
and size — the same fan-out `process_tic()` does for a TIC that
arrived from elsewhere, except this file *is* the origin hop, so there's
no prior SEEN-BY/PATH to inherit.

**In short: if you upload to a network-attached area, you are
broadcasting that file to every peer on that file echo, not just
filing it locally.** Purely local file areas (`network_id` is `None`)
are unaffected — nothing is queued for those.

Delivery happens on the next BinkP poll per peer. A sysop running this
BBS as a network hub can see the outbound queue's current
pending/failed counts on the **TIC / File Distribution** tab of **Admin
→ Echomail Networks → Hub Management** (`/admin/echomail/hub/`), which
links through to the **TIC Out Log** (`/admin/hatch-log`) for the full
per-item detail (which file, which peer, retry count, last error) — see
[doc 6](06-echomail.md) for the full Hub Management writeup. That
dashboard view is hub-operator-only (gated by `REGISTRY_MODE_ENABLED`);
the plain **Admin → TIC In/Out Log** audit pages above are available on
every install.

## FileFix — subscription requests from peers

FileFix is the file-echo counterpart to AreaFix (see
[doc 6 — Echomail](06-echomail.md)) — it lets a downstream peer manage
their own file-echo subscriptions by sending a netmail instead of the
hub sysop doing it by hand. It lives in `anetbbs/echomail/filefix.py`
and reuses AreaFix's exact command grammar.

A peer addresses a netmail to **`FileFix`** (also recognized:
`File Fix`, `FileMgr`) at your hub address, with the **AreaFix/FileFix
password in the Subject line** (per FTS-0024 — NOT in the body, same
convention as AreaFix) and one command per line in the body:

```
+FILES.GAMES        subscribe to a file echo
-FILES.GAMES        unsubscribe from a file echo
+ALL / -ALL         subscribe / unsubscribe to everything available
%LIST (or %QUERY)   reply with current subscriptions
%HELP               reply with a help/command summary
```

The bot replies with a netmail confirming what changed. If the
requester's FTN address matches a `BinkPNode` this BBS hosts as a hub
peer, the change is scoped to that peer's own `FileEchoSubscription`
rows (keyed by peer address, not a `BinkPNode` foreign key — a real
structural difference from AreaFix's `EchoAreaNode`) instead of the
global `FileArea.is_subscribed` flag.

**Password**: FileFix shares the same network-level password fields as
AreaFix — there's no separate `filefix_password`. Set `areafix_password`
(or leave it blank to fall back to `binkp_password`) on the network's
edit page; it covers both bots.

The sysop side of outbound FileFix requests (subscribe/unsubscribe
buttons on file-area management pages) queues the same kind of netmail
automatically — see `send_areafix_request(..., robot_name='FileFix')`
in `areafix.py` (FileFix reuses AreaFix's outbound sender directly).
Traffic is logged on the same **Admin → Echomail Networks → AreaFix
Log** page AreaFix uses (`/admin/echomail/areafix_log`) — a **Bot**
column and an AreaFix/FileFix filter distinguish the rows.

## Shareable links

Any user can mint an expiring share link for a file in an area they
have access to. **Tools → My File Shares**.
