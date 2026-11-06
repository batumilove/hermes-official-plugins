"""Real owner-private key custody, tested on the native POSIX filesystem."""
import os
import time

import pytest

from langfuse_plugin.proof_paths import PrivateKey

pytestmark = pytest.mark.skipif(not all(hasattr(os, name) for name in
    ("getuid", "pread", "O_NOFOLLOW", "O_DIRECTORY")), reason="native POSIX key custody required")


@pytest.fixture
def key_path(tmp_path):
    folder = tmp_path.resolve() / "proof-key"
    folder.mkdir(mode=0o700)
    path = folder / "key"
    path.write_bytes(b"synthetic-key".ljust(32, b"!"))
    path.chmod(0o600)
    return path


def test_private_key_retains_exact_identity_and_has_no_write_side_effects(key_path):
    before = key_path.read_bytes()
    with PrivateKey(str(key_path)) as key:
        assert key.value == before and key.valid()
        assert key_path.read_bytes() == before
        assert sorted(p.name for p in key_path.parent.iterdir()) == ["key"]
    assert not key.valid()
    assert key_path.read_bytes() == before


@pytest.mark.parametrize("mutation", ["bytes", "inode", "mode", "link"])
def test_key_mutation_is_permanently_invalid_even_if_bytes_restored(key_path, mutation):
    original = key_path.read_bytes()
    with PrivateKey(str(key_path)) as key:
        if mutation == "bytes":
            key_path.write_bytes(b"x" * 32)
        elif mutation == "inode":
            replacement = key_path.parent / "replacement"
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            replacement.replace(key_path)
        elif mutation == "mode":
            key_path.chmod(0o640)
        else:
            os.link(key_path, key_path.parent / "other-link")
        assert not key.valid()
        key_path.write_bytes(original)
        key_path.chmod(0o600)
        assert not key.valid()


@pytest.mark.parametrize("mutation", ["short", "long", "mode", "parent_mode", "symlink", "parent_symlink"])
def test_unsafe_key_inputs_fail_without_creating_or_removing_files(key_path, mutation):
    path = key_path
    if mutation in {"short", "long"}:
        key_path.write_bytes(b"x" * (31 if mutation == "short" else 33))
    elif mutation == "mode":
        key_path.chmod(0o644)
    elif mutation == "parent_mode":
        key_path.parent.chmod(0o755)
    elif mutation == "symlink":
        path = key_path.parent / "link"
        path.symlink_to(key_path)
    else:
        alias = key_path.parent.parent / "alias"
        alias.symlink_to(key_path.parent, target_is_directory=True)
        path = alias / "key"
    before = sorted(p.name for p in key_path.parent.iterdir())
    with pytest.raises((OSError, ValueError)):
        PrivateKey(str(path))
    assert sorted(p.name for p in key_path.parent.iterdir()) == before


def test_expired_and_future_keys_are_not_accepted(key_path):
    now = time.time()
    for modified in (now - 86401, now + 10):
        os.utime(key_path, (modified, modified))
        with pytest.raises(ValueError):
            PrivateKey(str(key_path), clock=lambda: now)


def test_monotonic_lifetime_cannot_be_extended_by_clock_rollback(key_path):
    now, tick = [time.time()], [0.0]
    with PrivateKey(str(key_path), clock=lambda: now[0], monotonic=lambda: tick[0]) as key:
        assert key.valid()
        tick[0] = 86401
        now[0] -= 1
        assert not key.valid()
        tick[0] = 0
        assert not key.valid()
