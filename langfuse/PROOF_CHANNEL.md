# Explicit collector-to-verifier proof transfer

The optional Linux proof channel connects the original retained Receipt to an
independent acceptance process on the same host. It adds no TCP listener, provider
call, backend polling, file provisioning or automatic cleanup. It is disabled by
default. Source tests do not authorize activation or establish live delivery.

The owner pre-provisions two separate private directories: one for receipts and
one for the socket/key. Every path component must be a real directory, with no
symlinks; each final directory must belong to the process UID and have mode 0700.
The key must already exist as a regular, single-link, owner-only 0600 file holding
32 random raw bytes. Never put the key in YAML, environment values, command-line
arguments or shared output. The socket and key cannot live in or below the receipt
directory. Use a generation-specific socket path. Existing paths are refused,
including stale sockets; an operator
must reconcile their exact owner before any separately authorized retirement.

```yaml
plugins:
  entries:
    langfuse:
      settings:
        receipts:
          enabled: true
          directory: /absolute/private/receipts
          proof_channel:
            enabled: true
            socket: /absolute/private/proofs/collector.sock
            key_file: /absolute/private/proofs/transfer.key
```

These paths are placeholders, not commands or deployment instructions. The native
socket path is limited to 107 encoded bytes. Activation requires a target-specific
plan covering the owning updater/lifecycle, exact loaded core/plugin identities,
private metadata, key distribution, retention owner, capacity, expiry and rollback.
No activation is performed by importing or registering the plugin.

The first instrumented root starts at most one listener worker per plugin runtime.
The public `PluginContext.on_unload` cleanup registration must be available and
active; older hosts may use local receipts but cannot enable this channel. The
worker explicitly binds its owning profile, empty secret scope and multiplex mode.
It inherits neither a launch profile's secrets nor the first turn's ContextVars.
SDK tracing remains fail-open when receipt/channel admission is refused.

One request per connection has finite framing and time bounds: 8 KiB requests,
128 KiB responses, a one-second server I/O deadline and two seconds for a consumer
exchange, including mandatory frame EOF. These are socket deadlines, not a hard
watchdog against a blocked OS or collector lock. The listener backlog is two. Peer
credentials must identify the same OS UID. HMAC additionally binds the producer's
PID/start/boot tuple, profile, selected turn/trace/Receipt digest, operation, fresh
random request ID and request hash. Requests expire after 30 seconds with five
seconds of clock skew. Each server generation admits at most 256 distinct
authenticated requests; replayed requests are refused. There is no reply cache.

`describe` freshly collects post-quiescence evidence and authenticates its
registration digest. It grants no delivery verdict. `transfer` requires that full
binding and freshly re-reads the original Receipt through the core collector's
single-use transfer operation. Pending callbacks, failed/cancelled turns,
abandonment, changed registration, late invalidation and lost originals cannot
be replaced by saved receipt JSON or caller assertions.

The owner runs `live_delivery.LiveDeliveryAttempt` as a separate process on the
producer's Linux host, using the same private key file and an explicitly configured
`ObservationReader`. Its input pins come from independently observed producer and
profile identity plus the immutable selected Receipt. The API accepts no saved
transfer input. It performs fresh authenticated describe/transfer exchanges, then
the separate HTTPS backend readback. An attempt is consumed on every outcome;
there is no automatic retry, saved-proof replay or acceptance after close. Only
the fixed `DeliveryCheck` verdict/reason/counts belong in shared output. Profiles,
producer details, digests, envelopes and IDs remain private correlation metadata.

Keys are pinned by namespace, inode, permissions, metadata and content. The lease
expires no later than 24 hours after file modification, with a monotonic ceiling
that wall-clock rollback cannot extend. Observed key/config/namespace changes
permanently revoke that listener. Restoring bytes does not revive it. Rotate through
an owner-approved unload/provision/reload, never by silently replacing a live key.
No secure erasure of Python heap copies is claimed.

Unload invalidates authority before stopping acceptance and active connections.
Shutdown waits at most two seconds for the worker, then closes its handles. The
socket pathname is always retained: Linux has no inode-conditional pathname unlink,
so checking and then unlinking could delete a concurrent owner's replacement.
Owner-controlled retirement is separate from successful worker termination. If
termination is unproved, key descriptors and the inode pin also remain held. Forked
copies reject requests before inherited locks and close their duplicate handles
without shutdown or unlink. An `atexit` fallback exists after listener acquisition;
it does not make forced process death a quiescence or delivery proof.

The existing 16-turn/300-second in-memory retention and receipt-directory
256-file/64-KiB-per-file/24-hour refusal bounds still apply. They are capacity and
admission bounds, not an implemented deletion policy. Before enabling, the owner
must provide and exercise expiry/custody for every receipt, key, derived private
copy and controller evidence set. Stop on missing ownership or retention; do not
extend lifetimes or add a cleanup job implicitly. Backend credentials and observed
API compatibility also require independent verification for the selected project.

Offline tests use real Linux sockets, `/proc` identity, core host boundaries and
original Receipt objects, with synthetic backend responses. They cover delayed
callbacks, cancellation, shutdown, stale/replayed proofs, key/namespace changes,
unload races, backend failure and the single-attempt acceptance path. They do not
establish real SDK export, authenticated production API compatibility, deployment,
cross-host proof transfer or live acceptance. Those remain canary gates.
