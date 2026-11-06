# Explicit backend readback

`backend_readback.ObservationReader` reads one selected trace from the Langfuse
v2 Observations API. `delivery_verification.DeliveryVerifier` consumes the core
collector's serialized HMAC transfer and compares its captured inventory with
that independent readback. These are operator/controller APIs, with no automatic
requests, configuration changes, background polling, directory creation or cleanup.
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
retry, grace-period poller, API downgrade or fallback to HTTP. The operator must
confirm that the selected deployment actually supports the v2 endpoint and the
documented response schema. A version label or a route requiring authentication
alone does not establish authenticated compatibility.

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
