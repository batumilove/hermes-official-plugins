# Explicit backend readback

`backend_readback.ObservationReader` reads one selected trace from an explicitly
selected Langfuse Observations API (v2 by default). `delivery_verification.DeliveryVerifier` consumes the core
collector's serialized HMAC transfer and compares its captured inventory with
that independent readback. These are operator/controller APIs, with no automatic
requests, configuration changes, background polling, directory creation or automatic cleanup.
The existing receipt feature remains disabled by default.

The signed-transfer consumer requires the optional host turn-evidence API. The
receipt interoperability workflow pins merged Hermes core
`d5212091d0f698d90c1eb96e96faa7bc049876c0` and requires those imports before
running every receipt contract on Linux. The general upstream-host matrix still
tests the ordinary SDK plugin and portable backend reader; it skips optional
API tests only when those host modules are absent. Producer Receipt tests run
on Linux because their identity is the real `/proc` PID/start/boot tuple.

The operator must provide the exact HTTPS base URL, read credentials and expected
project ID, and independently pin the profile, producer PID/start/boot tuple,
turn digest, trace ID, receipt digest and registration digest. Never derive the
expected binding from the untrusted transfer being verified. Keep keys, bindings,
wire bytes and observation IDs in owner-private storage; only the fixed verdict,
reason and bounded counts belong in a shared report. No response body is retained.

```python
from langfuse_plugin.backend_readback import ObservationReader
from langfuse_plugin.delivery_verification import DeliveryVerifier

# All arguments come from the owning controller's private, approved configuration.
reader = ObservationReader(base_url, public_key, secret_key, project_id=project_id)
consumer = DeliveryVerifier(transfer_key, reader)
check = consumer.verify(wire_bytes, expected_binding=independently_pinned_binding)
```

The module name above is the test alias. A real directory plugin is imported by
Hermes under its loader-assigned package; use that package's sibling modules.

The [Langfuse v2 API](https://langfuse.com/docs/api-and-data-platform/features/observations-api)
supports selecting `core,basic` fields and cursor pagination. The `basic` group
provides the validated `isRootObservation` boolean; other basic fields are discarded. Every query is
restricted to the selected trace and the signed receipt's creation/seal window,
with a fixed five-second margin. Returned start and end timestamps must fit that
window. Physical parentage remains available as `parentObservationId`. For the exact
signed Receipt root only, an explicit `isRootObservation: true` permits a physical
parent outside the captured inventory to represent the SDK's application-root
boundary. Its logical Receipt parent is null. A self/internal parent, a second
application root, an explicit false root flag, or wrong child parent cannot pass.
An external root parent without that explicit boolean remains unverified.
An exhausted cursor establishes completeness of that bounded query only.
It cannot establish completeness of uninstrumented work or observations outside
the selected time window.

The reader follows every cursor, including after an empty page. It refuses
duplicate IDs, repeated/invalid cursors, wrong trace/project, malformed timestamps,
oversized responses, more than 256 observations or an unfinished page sequence.
An observation with no end timestamp remains open. Extra/missing/wrong-parent
observations cannot produce `captured_inventory_delivered`. Unknown fields,
including any unexpected input/output, are discarded rather than persisted.

The default query budget is five seconds and eight pages, with ceilings of ten
seconds and sixteen pages, and one MiB per response. HTTPS certificate validation
is mandatory; redirects are refused before credentials can be forwarded. Socket
operations have finite timeouts and elapsed time is checked between operations.
This is not a hard process-level watchdog against a blocked OS call. There is no
retry, grace-period poller, automatic API downgrade or fallback to HTTP. The operator must
confirm that the selected deployment actually supports the selected endpoint and the
documented response schema. A version label or a route requiring authentication
alone does not establish authenticated compatibility.

## Self-hosted v3: explicit v1 selection

For a deployment that supports v1 rather than v2, construct the reader with
`api_version="v1"`. This is a selected contract, never a fallback after an error.
The query retains the same trace/project/time, byte, observation and elapsed bounds.
Every numbered page must agree on integer page/limit/total fields; counts must be
stable, each page must have its full expected length, and the final inventory must
equal the declared total. Missing/changed totals, duplicate IDs and page-limit
exhaustion remain unverified. No positive prefix can be accepted as complete.

The v1 schema lacks v2's logical-root boolean. New plugin roots therefore carry
the fixed boolean `metadata.hermes_receipt_root=true` through the normal SDK.
The marker is not propagated to children. The v1 reader validates that marker's
type and exposes it only as root evidence; the verifier still requires the
authenticated exact root/trace/project pins and rejects marked children or an
internal physical parent. A marker does not authenticate a receipt or authorize
queries by itself. Older roots without a marker and with an external physical
parent remain unverified. v2 continues using its server logical-root field.

## Explicit retirement of one synthetic canary

`canary_cleanup.CanaryTraceRetirement` is an inert, one-use controller utility.
It does not implement project-wide retention or run on normal turns. A separately
approved parent supplies its fresh random `telemetry-canary-<uuid>` task identity
and independently verified trace/root/project pins. The parent must first stop
and reap the original producer; the utility also refuses while that PID exists
(including reuse), on another creator PID, or after its 60-second deadline.

Before its single DELETE, it reads the exact root and trace and validates the
project, root marker, random task identity, Hermes source, canary platform and
metadata-only capture. It may retire an owned open root left by an interrupted
canary; retirement is distinct from successful delivery. Wrong ownership or
identity prevents deletion. Network, framing, schema and size failures remain
fixed private diagnostics. Before DELETE, an exclusive, fsynced private journal
binds the exact task, trace, root, project, endpoint and original time window.
The journal directory must outlive the managed private generation. Keep that
directory and claim until recovery and evidence retention are reconciled; deleting
or replacing them would lose the cross-process fence. An ambiguous DELETE is not
automatically retried, even by a fresh object.

When normal receipt sealing failed, `discover()` can locate the root using the
parent's pre-export random task identity and bounded time window. It accepts only
one owned trace (including at most two matching roots from the SDK root-open
fallback). Wrong metadata, different traces, truncated pages or larger counts
refuse cleanup. No matching row means unobserved/pending, not successful cleanup.

Discovery, project/trace reads, DELETE and the final observation check share one
reader-bound budget: ten requests, a 60-second original expiry and a 256KiB cap
on every response. Discovery and scope reconstruction with the same reader
cannot renew this budget. A fresh authorized cleanup worker creates one fresh
reader/read budget; the owner limits the complete attempt to three such workers,
and the durable DELETE claim remains shared across them.

The utility checks trace absence up to four times and independently requires an
exact empty numbered observation page (`limit=1`, zero items and zero pages).
Any nonempty or inconsistent inventory refuses retirement without fetching more
pages. This empty-query check uses the same transport and budget as every other
cleanup request. A deletion acknowledgement alone is
`canary_deletion_pending`, never retirement. Deferred deletion requires an
owner-bound read-only recovery record; it does not permit another export or an
automatic repeated DELETE. `from_journal()` rechecks the full claim and preserves
the original time window. `confirm()` authenticates the currently associated
project before checking trace/observation absence, so different project credentials
cannot turn a 404 into retirement. Reports distinguish a durable deletion claim
from DELETE attempts in the current process. The parent must verify its own
original manager/kernel lifecycle evidence and retain the pre-export nonce and
producer identity before initializing tracing. This utility alone cannot prove
those host conditions. The complete private controller integration must be
reviewed before activation.

API retirement is not proof of physical erasure, removed ingestion objects,
expired backups or unrelated derived copies. Those remain part of the separately
approved backend retention/recovery contract. Existing project retention is
unchanged. No actual backend deletion is performed by importing or testing this
module.

`DeliveryVerifier` first validates HMAC, freshness, exact identity pins, original
snapshot digest and normal terminal proof. A bad proof never queries the backend.
Each accepted nonce is consumed before the query, including a failed query.
An authenticated receipt whose query window exceeds the reader's bounds returns
`unverified` with reason `invalid_read_window`, distinct from a bad transfer.
Its nonce remains consumed; this diagnostic does not grant a retry.
The same consumer instance must own the entire bounded attempt. Nonces are held
in memory only: restarting the consumer is not persistent replay protection or
permission to reuse a proof. The optional [local proof channel](PROOF_CHANNEL.md)
supplies request-bound provenance from a live retained collector. Its
`LiveDeliveryAttempt` API accepts one independently pinned Receipt, requests a fresh
transfer and runs this reader; it accepts no saved transfer input. Key
provisioning/rotation, private evidence custody and owner-approved expiry remain
deployment prerequisites. Caller booleans and saved receipts alone cannot supply
those requirements.

Offline tests exercise synthetic signed proofs, parser and pagination failures,
and actual loopback TLS/authentication, redirect refusal and response bounds.
They do not establish delivery by the real SDK, remote proof transport, production
activation or backend acceptance for a live turn. Those remain separate gates.
