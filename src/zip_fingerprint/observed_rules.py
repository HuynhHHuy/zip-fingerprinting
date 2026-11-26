"""Fingerprint profiles observed in this project's own native experiments.

These profiles are **not** data from Um et al. (2021): ``rules.py`` keeps the paper's
Tables 6 and 7 verbatim. Each profile here records the run and evidence it was measured
from. They are used only when a caller asks for them (``ProvenanceTracker(rules=...)``
or ``provenance --observed-profiles``); default classification and tracking ignore them.

Evidence: docs/evaluation/sw2-screening-2026-11-26.md (issue #35).
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple

from zip_fingerprint.constants import EXTRA_HEADER_UNICODE_PATH, HostOS
from zip_fingerprint.rules import FingerprintRule

CATALOG_PAPER = "paper"
CATALOG_OBSERVED = "observed"


@dataclass(frozen=True)
class ObservedProfile:
    """A rule measured natively, with the provenance of the measurement."""

    rule: FingerprintRule
    source: Dict[str, str]


# Bandizip 7.47.0.1 deleting an entry from a 7-Zip 26.04 archive rewrites every survivor:
# the 0x000A NTFS block is dropped and only 0x7075 remains, for non-ASCII names. This
# layout differs from an archive Bandizip creates (paper profile: CDH 0x000A [+ 0x7075]).
BANDIZIP_REWRITE = ObservedProfile(
    rule=FingerprintRule(
        target_os="Windows",
        application="Bandizip 7.47 (rewrite, observed)",
        host_os_code=HostOS.MSDOS_WINDOWS,
        data_descriptor_required=False,
        local_extra_ids=(),
        central_extra_ids=(),
        local_extra_ids_unicode=(EXTRA_HEADER_UNICODE_PATH,),
        central_extra_ids_unicode=(EXTRA_HEADER_UNICODE_PATH,),
        notes="Observed natively; not part of Um et al. (2021).",
    ),
    source={
        "run": "run-sw2-_kiollnq",
        "confirmation_run": "run-sw2-gtjtd6ue",
        "cell": "S6",
        "sw1": "7-Zip 26.04",
        "sw2": "Bandizip 7.47.0.1 (portable)",
        "operation": "delete target.txt",
        "date": "2026-11-26",
        "after_sha256": "fefce78ded371e07ba2d5e9b6e01349a6a5a57f00199edf788a098ee8a55e113",
        "evidence": (
            "https://github.com/HuynhHHuy/zip-fingerprinting/releases/tag/"
            "evidence-ph4-prov-002-sw2-2026-11-26"
        ),
    },
)

OBSERVED_PROFILES: Tuple[ObservedProfile, ...] = (BANDIZIP_REWRITE,)


def get_observed_rules() -> List[FingerprintRule]:
    """Return the observed rules, separate from ``rules.get_all_rules()``."""
    return [profile.rule for profile in OBSERVED_PROFILES]


def catalog_of(environment: Tuple[str, str]) -> str:
    """Name the catalog an environment comes from: ``"observed"`` or ``"paper"``."""
    observed = {(rule.target_os, rule.application) for rule in get_observed_rules()}
    return CATALOG_OBSERVED if tuple(environment) in observed else CATALOG_PAPER
