from pathlib import Path

import pytest

from incidentgate.evaluation.sabotage_v3_runner import (
    PublicationRefusal,
    TypedPublicationAudit,
    _atomic_write,
    _binomial,
    default_runtime_audit,
)


def test_wilson_keeps_raw_zero_denominator_visible() -> None:
    zero = _binomial(0, 0)
    assert (zero.numerator, zero.denominator, zero.rate) == (0, 0, None)
    full = _binomial(1, 1)
    assert full.rate == 1
    assert 0 <= full.wilson_low <= full.wilson_high <= 1


def test_typed_audit_refuses_cache_mutation_before_projection() -> None:
    with pytest.raises(PublicationRefusal, match="cache audit mutated"):
        TypedPublicationAudit((), (), (), "a" * 64, "b" * 64)


def test_atomic_write_does_not_leave_partial_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    _atomic_write(target, b"complete")
    assert target.read_bytes() == b"complete"
    assert not list(tmp_path.glob(".sabotage-v3-*"))


def test_default_runtime_audit_is_wired_to_the_typed_cache_only_audit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import incidentgate.evaluation.model_replay_monitor_audit as audit_module

    seen: list[object] = []
    sentinel = object()
    threshold = object()

    def fake_audit(*args: object) -> object:
        seen.extend(args)
        return sentinel

    monkeypatch.setattr(audit_module, "build_cache_only_publication_audit", fake_audit)

    result = default_runtime_audit("db-free", tmp_path, threshold, "a" * 64)  # type: ignore[arg-type]

    assert result is sentinel
    assert seen == ["db-free", tmp_path, threshold, "a" * 64]
