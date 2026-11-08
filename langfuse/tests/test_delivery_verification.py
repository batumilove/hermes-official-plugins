"""Synthetic whole-path proof authentication and independent backend reconciliation."""
import hashlib
import hmac
import importlib.util
import json
from datetime import datetime, timezone
from email.message import Message

import pytest

if importlib.util.find_spec("hermes_cli.plugins_turn_evidence_collector") is None:
    pytest.skip("Host lacks the optional transfer verifier; pinned-core CI exercises it",
                allow_module_level=True)

from langfuse_plugin.backend_readback import ObservationReader
from langfuse_plugin.delivery_verification import DeliveryVerifier


TRACE, ROOT = "a" * 32, "b" * 16
NOW = 1793977003.0
KEY = b"synthetic-only-shared-secret-key!!"


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def signed(payload):
    return canonical(dict(payload, signature=hmac.new(KEY, canonical(payload), hashlib.sha256).hexdigest()))


@pytest.fixture
def transfer():
    producer = {"pid": 42, "start_ticks": 123, "boot_id": "1" * 8 + "-" + "1" * 4 + "-" + "1" * 4 + "-" + "1" * 4 + "-" + "1" * 12}
    snapshot = {"schema": 1, "trace_id": TRACE, "root_id": ROOT, "turn_sha256": "e" * 64,
                "producer": producer, "created_at": NOW - 3, "sealed_at": NOW - 1,
                "terminal_reason": "normal", "inventory_valid": True, "local_complete": True,
                "observations": {ROOT: {"parent_id": None, "ended": True}}}
    digest = hashlib.sha256(canonical(snapshot)).hexdigest()
    proof = {"valid": True, "receipt_sha256": digest, "producer": producer, "issued_at": NOW - 0.5}
    binding = {"trace_id": TRACE, "turn_sha256": "e" * 64, "profile": "synthetic-profile",
               "producer": producer, "receipt_sha256": digest, "registration_sha256": "f" * 64}
    payload = dict(binding, schema=1, kind="turn_evidence_transfer", nonce="c" * 32,
                   issued_at=NOW, proof=proof, snapshot=snapshot)
    return payload, binding


class Backend:
    def __init__(self, rows, api_version="v2"):
        self.rows, self.calls, self.api_version = rows, 0, api_version

    def open(self, request, *, timeout):
        import io
        self.calls += 1
        meta = (dict(page=1, limit=100, totalItems=len(self.rows),
                     totalPages=1 if self.rows else 0) if self.api_version == "v1" else {})
        data = json.dumps({"data": self.rows, "meta": meta}).encode()
        response = io.BytesIO(data)
        response.headers = Message()
        response.headers["Content-Length"] = str(len(data))
        response.status = 200
        return response


def setup(rows, *, api_version="v2"):
    reader = ObservationReader("https://synthetic.invalid", "pk-test", "sk-test",
                               project_id="synthetic-project", api_version=api_version)
    backend = Backend(rows, api_version)
    reader._opener = backend
    return DeliveryVerifier(KEY, reader, clock=lambda: NOW), backend


def row(**changes):
    def stamp(t):
        return datetime.fromtimestamp(t, timezone.utc).isoformat()
    return dict({"id": ROOT, "traceId": TRACE, "projectId": "synthetic-project",
                 "parentObservationId": None, "startTime": stamp(NOW - 2),
                 "endTime": stamp(NOW - 1)}, **changes)


def test_exact_authenticated_snapshot_and_backend_match(transfer):
    payload, binding = transfer
    verifier, backend = setup([row()])
    result = verifier.verify(signed(payload), expected_binding=binding)
    assert result.verdict == "captured_inventory_delivered"
    assert result.expected_count == result.observed_count == 1 and result.pages == 1
    assert backend.calls == 1
    # This verifier's receipt can be consumed only once, even on a later call.
    assert verifier.verify(signed(payload), expected_binding=binding).verdict == "unverified"
    assert backend.calls == 1


@pytest.mark.parametrize("marker,expected", [
    (True, "captured_inventory_delivered"), (False, "unverified"), (None, "unverified"),
    ("true", "unverified")])
def test_v1_external_root_requires_explicit_marker_and_authenticated_root(transfer, marker, expected):
    payload, binding = transfer
    verifier, backend = setup([row(parentObservationId="d" * 16,
                                  metadata={"hermes_receipt_root": marker})], api_version="v1")
    result = verifier.verify(signed(payload), expected_binding=binding)
    assert result.verdict == expected and backend.calls == 1


def test_v1_root_marker_cannot_turn_a_child_into_the_authenticated_root(transfer):
    payload, binding = transfer
    verifier, _ = setup([row(id="c" * 16, metadata={"hermes_receipt_root": True})], api_version="v1")
    assert verifier.verify(signed(payload), expected_binding=binding).reason == "invalid_root_lineage"


@pytest.mark.parametrize("case", ["signature", "stale", "profile", "producer", "digest",
                                  "registration", "snapshot_mutation", "invalid_proof", "shutdown"])
def test_bad_proof_never_queries_backend(transfer, case):
    payload, binding = transfer
    if case in {"profile", "producer", "digest", "registration"}:
        key = {"digest": "receipt_sha256", "registration": "registration_sha256"}.get(case, case)
        binding[key] = "wrong"
    elif case == "stale":
        payload["issued_at"] = NOW - 121
    elif case == "snapshot_mutation":
        payload["snapshot"]["observations"][ROOT]["ended"] = False
    elif case == "invalid_proof":
        payload["proof"]["valid"] = False
    elif case == "shutdown":
        payload["snapshot"]["terminal_reason"] = "shutdown"
    wire = signed(payload)
    if case == "signature":
        wire = wire.replace(b'"signature":"', b'"signature":"0')
    verifier, backend = setup([row()])
    assert verifier.verify(wire, expected_binding=binding).verdict == "unverified"
    assert backend.calls == 0


@pytest.mark.parametrize("rows, verdict", [([], "mismatch"), ([row(endTime=None)], "unverified"),
                                          ([row(), row(id="d" * 16)], "mismatch"),
                                          ([row(parentObservationId="d" * 16)], "unverified")])
def test_backend_http_success_is_not_delivery(transfer, rows, verdict):
    payload, binding = transfer
    verifier, _ = setup(rows)
    assert verifier.verify(signed(payload), expected_binding=binding).verdict == verdict


def test_failed_backend_acquisition_consumes_proof_without_automatic_retry(transfer):
    payload, binding = transfer
    verifier, backend = setup([row(traceId="d" * 32)])
    result = verifier.verify(signed(payload), expected_binding=binding)
    assert result.verdict == "unverified" and result.reason == "invalid_observation"
    backend.rows = [row()]
    assert verifier.verify(signed(payload), expected_binding=binding).verdict == "unverified"
    assert backend.calls == 1


@pytest.mark.parametrize("wire", [b"{}", b"[]", b"not json", b"x" * 131073])
def test_malformed_wire_is_content_free_and_does_not_query(wire, transfer):
    _, binding = transfer
    verifier, backend = setup([row()])
    result = verifier.verify(wire, expected_binding=binding)
    assert result.verdict == "unverified" and backend.calls == 0


def test_all_expected_identity_pins_are_mandatory(transfer):
    payload, binding = transfer
    for field in ("receipt_sha256", "registration_sha256"):
        incomplete = dict(binding)
        incomplete.pop(field)
        verifier, backend = setup([row()])
        assert verifier.verify(signed(payload), expected_binding=incomplete).verdict == "unverified"
        assert backend.calls == 0


@pytest.mark.parametrize("profile", [None, "", "   ", "missing"])
def test_signed_transfer_cannot_omit_profile_authority(transfer, profile):
    payload, binding = transfer
    if profile == "missing":
        payload.pop("profile")
        binding.pop("profile")
    else:
        payload["profile"] = binding["profile"] = profile
    verifier, backend = setup([row()])
    assert verifier.verify(signed(payload), expected_binding=binding).verdict == "unverified"
    assert backend.calls == 0


@pytest.mark.parametrize("field", ["profile", "producer", "receipt_sha256", "registration_sha256",
                                   "turn_sha256", "trace_id"])
def test_well_formed_mismatching_pins_reach_authentication_boundary(transfer, field):
    payload, binding = transfer
    wire = signed(payload)
    if field == "producer":
        binding[field] = dict(binding[field], pid=43)
    elif field == "profile":
        binding[field] = "other-synthetic-profile"
    else:
        binding[field] = "0" * (32 if field == "trace_id" else 64)
    verifier, backend = setup([row()])
    result = verifier.verify(wire, expected_binding=binding)
    assert result.verdict == "unverified" and result.reason == "invalid_transfer"
    assert backend.calls == 0


def test_authenticated_receipt_window_failure_is_distinct_and_not_retried(transfer):
    payload, binding = transfer
    payload["snapshot"]["created_at"] = NOW - 86399
    digest = hashlib.sha256(canonical(payload["snapshot"])).hexdigest()
    payload["proof"]["receipt_sha256"] = payload["receipt_sha256"] = binding["receipt_sha256"] = digest
    verifier, backend = setup([row()])
    wire = signed(payload)
    result = verifier.verify(wire, expected_binding=binding)
    assert result.verdict == "unverified" and result.reason == "invalid_read_window"
    assert backend.calls == 0
    # Authentication consumed this nonce. A bounded-query failure grants no retry.
    assert verifier.verify(wire, expected_binding=binding).reason == "invalid_transfer"
    assert backend.calls == 0


def test_explicit_application_root_allows_only_an_external_physical_parent(transfer):
    payload, binding = transfer
    verifier, backend = setup([row(parentObservationId="d" * 16, isRootObservation=True)])
    result = verifier.verify(signed(payload), expected_binding=binding)
    assert result.verdict == "captured_inventory_delivered"
    assert result.expected_count == result.observed_count == 1 and backend.calls == 1


@pytest.mark.parametrize("changes", [
    {"parentObservationId": "d" * 16},
    {"parentObservationId": "d" * 16, "isRootObservation": False},
    {"parentObservationId": ROOT, "isRootObservation": True},
    {"isRootObservation": False},
])
def test_missing_or_contradictory_root_lineage_never_passes(transfer, changes):
    payload, binding = transfer
    verifier, _ = setup([row(**changes)])
    assert verifier.verify(signed(payload), expected_binding=binding).verdict != "captured_inventory_delivered"


@pytest.mark.parametrize("case", ["multiple_roots", "internal_root_parent", "wrong_child_parent"])
def test_application_root_marker_cannot_hide_captured_lineage_errors(transfer, case):
    payload, binding = transfer
    child = "c" * 16
    payload["snapshot"]["observations"][child] = {"parent_id": ROOT, "ended": True}
    digest = hashlib.sha256(canonical(payload["snapshot"])).hexdigest()
    payload["receipt_sha256"] = binding["receipt_sha256"] = digest
    payload["proof"]["receipt_sha256"] = digest
    rows = [row(parentObservationId="d" * 16, isRootObservation=True),
            row(id=child, parentObservationId=ROOT, isRootObservation=False)]
    if case == "multiple_roots":
        rows[1]["isRootObservation"] = True
    elif case == "internal_root_parent":
        rows[0]["parentObservationId"] = child
    else:
        rows[1]["parentObservationId"] = "e" * 16
    verifier, _ = setup(rows)
    assert verifier.verify(signed(payload), expected_binding=binding).verdict != "captured_inventory_delivered"
