# Experimental per-trace delivery receipts

Prepared candidate only. This feature is disabled by default and does not query a backend,
install dependencies, start a producer, create a directory, delete evidence, or enable export.

## Scope of the verdict

The problem is that a recent session trace does not establish which process produced a given
turn or whether its expected observations arrived. An opt-in local receipt records the actual
Linux PID, kernel process start ticks and boot ID, deterministic trace ID, hashed turn ID, root
observation ID, child IDs/parents and successful local SDK end calls. No input/output, tool name,
endpoint, credential, session ID or raw exception is written by this feature. These identifiers
remain sensitive correlation metadata and belong only in owner-private evidence storage.

The expected set includes SDK observation handles successfully created through this plugin's
root/child adapter. It does NOT enumerate all agent work: hooks dropped before the plugin,
SDK creation failures, sampling, other producers, failed receipt writes and process crashes can
have no receipt. A missing receipt is UNKNOWN. A locally ended handle is not a backend receipt.
Parentage currently reflects the plugin's root-direct child construction, not arbitrary trees.

`reconcile(receipt, backend, terminal_proof=proof)` returns `captured_inventory_delivered` only for an exact bounded inventory match.
It must never be reported as all-turn, all-profile or whole-window delivery completeness.
A deployment/producer identity must separately be bound to the receipt's PID/start/boot tuple;
an inherited service invocation environment variable is deliberately not treated as identity.

## Separate activation prerequisites

Do not change the installed plugin or launch configuration as part of candidate testing.
Before any future activation, independently review the exact candidate, identify the profile,
producer and owning updater, establish the permitted metadata and storage owner, and use the
normal source/catalog publication and lifecycle controls. This candidate does not authorize
activation, gateway restart, a synthetic request or a backfill.

Only the served profile's plugin YAML settings may enable `receipts.enabled` and
supply `receipts.directory` under `plugins.entries.langfuse.settings`. Provision a
dedicated absolute directory owned by the producer
user, mode 0700; all path components must be nonsymlinks. Never reuse a shared or general log
directory. No directory is created automatically. If profile scope is absent/unavailable,
receipt collection stays disabled rather than falling back to another profile's secrets.

Set and verify an owner-managed expiry policy of at most 24 hours for receipts and derived copies before enabling. No deletion is implemented here: unknown expiry
or custody means leave the feature disabled. Expired existing evidence stops new writes;
capacity/permission/lock/disk failures leave evidence unavailable, without blocking the agent.
The writer uses a nonblocking interprocess advisory lock. Filesystem latency itself is not a
hard real-time bound; test the destination filesystem before activation.

Limits are 256 observation entries per trace, 256 receipt files plus one writer lock, 64 KiB per receipt (at most 16 MiB payload), and 24-hour acceptance
age. Overflow invalidates the inventory. The writer never replaces a receipt or follows a
symlink, and leaves a partial failed write visibly unusable. Directory debris or unsafe entries
stop collection until the owner reconciles them. No automated cleanup/retry/job is added.

## Offline reconciliation input

A saved receipt is PROVISIONAL forever on its own. After independent terminal/quiescence
proof for the selected turn, the owning collector must obtain `Receipt.terminal_proof()` from
the original producer's exact live Receipt object, then freshly read the snapshot with
`read_receipt(directory, trace_id)`. Pass that proof separately to `reconcile()`. It binds the
canonical receipt SHA256 and producer identity to the current lock-protected validity state.
Late events and adapter exceptions permanently invalidate that state without any filesystem
write. Consequently disk-full/permission failures during late events cannot leave an acceptable
stale receipt, and no late marker files can grow outside the capacity limit.

The proof must be collected AFTER quiescence, not cached when the root ends. The method does
not establish quiescence or freeze future events. If a later event is possible, if the Receipt
object is lost, or if the producer exits before this proof is collected, report UNKNOWN. Process
exit alone is not a terminal validity proof. Reader booleans, quiet logs and a saved JSON file
cannot reconstruct lost in-memory invalidations. Proof provenance must be authenticated by the
owning collector; the pure offline function cannot authenticate arbitrary caller-created JSON.

The local runtime implements collector ownership and bounded object retention,
with the original reader retained through host-turn quiescence. The explicit
[backend reader](BACKEND_ACCEPTANCE.md) authenticates an existing signed transfer
and independently queries Langfuse v2. The optional [local proof channel](PROOF_CHANNEL.md)
connects that retained collector to a separate same-host verifier process using
request-bound authentication. Owner-controlled key provisioning, storage retention,
exact loaded versions and live backend compatibility still require an activation
plan and bounded acceptance evidence. Automatic activation remains disabled.

The caller must build a private backend envelope from the installed API's actual readback:

```json
{
  "trace_id": "32 lowercase hex digits",
  "complete": true,
  "producer_terminal_verified": true,
  "local_receipt_current": true,
  "observations": [
    {"id": "16 lowercase hex digits", "trace_id": "32 lowercase hex digits",
     "parent_id": null, "ended": true}
  ]
}
```

Those booleans are evidence requirements, not defaults to set unconditionally. `complete` means
all pages for this exact trace were retrieved without truncation under a declared finite grace
period and cap. Normalize `ended` only from validated backend terminal timestamps/status, never
from HTTP success or observation existence. `producer_terminal_verified` requires a separately
validated owning lifecycle/turn completion record. `local_receipt_current` requires the fresh
private reader after that boundary, together with the separate producer validity proof.
The explicit v2 API adapter derives its query result from actual readback;
it supplies no automatic live acceptance workflow.

Every expected ID must appear exactly once, with the same trace, parent and terminal state;
missing, extra, duplicate, wrong-parent and wrong-trace rows prevent a success verdict. Open
children, all session-finalization boundaries, shutdown/eviction/error completion, malformed or expired evidence are unverified.
No successful SDK flush, clean log sample or root completion substitutes for these checks.

## Offline tests

`tests/test_delivery_receipts_offline.py` uses only synthetic handles and a temporary private
directory. Run with an isolated HOME, no credentials and network denial before importing the
plugin. It covers positive reconciliation, missing/extra/duplicate/wrong-parent/wrong-trace
observations, incomplete/expired evidence, producer identity validation, privacy, lost-invalidation storage failures, adapter faults racing finalization, actual shutdown
hooks, proof binding, late events without storage growth, storage bounds,
writer contention, symlink/permission failures, disabled configuration and failed SDK end calls.
These tests exercise receipt mechanics, not the real SDK exporter or backend delivery.


## Isolated runtime wiring candidate

The runtime candidate uses plugin settings `receipts.enabled: true` and an
absolute `receipts.directory` under `plugins.entries.langfuse.settings`.
The operator pre-provisions that directory with the Receipt's private ownership
and permissions. The former receipt-directory environment switch is retired.
No settings are changed by registration. Disabled is the default.

Each SDK root attaches one collector to the existing host turn. Registration must
finish before attachment. The adapter keeps at most 16 turn collectors for 300
seconds, then lazily drops ownership at the next adapter operation. Receipt disk
retention remains the original module's separate bound; this adapter does not
perform operator cleanup. Existing SDK root teardown ends/seals its Receipt while
the runtime retains its original reader beyond removal from the SDK trace map.
The local operator/controller can call `runtime.collect(turn_id)` after host exit;
open turns or outstanding callbacks cannot produce a collected proof. Reused
turn text matching multiple boundaries is rejected. There is no background poller.

With no `proof_channel` opt-in this remains local wiring only. The optional channel
requires an existing private key, socket directory and active host unload cleanup;
the plugin provisions none of them. A collected proof is local evidence, not a
delivery verdict. Detached SDK work remains outside the reviewed callback boundary.
Runtime activation and actual backend acceptance require a separate bounded plan.
