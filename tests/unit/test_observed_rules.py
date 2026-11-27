"""The observed-profile catalog stays separate from the paper catalog (Um et al., 2021)."""

from zip_fingerprint.observed_rules import (
    OBSERVED_PROFILES,
    catalog_of,
    get_observed_rules,
)
from zip_fingerprint.rules import get_all_rules

REWRITE = ("Windows", "Bandizip 7.47 (rewrite, observed)")
S6_AFTER_SHA256 = "fefce78ded371e07ba2d5e9b6e01349a6a5a57f00199edf788a098ee8a55e113"


def test_observed_rules_are_not_in_paper_catalog():
    paper = get_all_rules()
    observed = get_observed_rules()
    assert len(paper) == 12
    assert not any(rule in paper for rule in observed)
    paper_envs = {(rule.target_os, rule.application) for rule in paper}
    assert not paper_envs & {(rule.target_os, rule.application) for rule in observed}


def test_bandizip_rewrite_profile_values():
    (rule,) = get_observed_rules()
    assert (rule.target_os, rule.application) == REWRITE
    assert rule.host_os_code == 0
    assert rule.data_descriptor_required is False
    assert rule.local_extra_ids == ()
    assert rule.central_extra_ids == ()
    assert rule.local_extra_ids_unicode == (0x7075,)
    assert rule.central_extra_ids_unicode == (0x7075,)
    assert rule.nanosecond_pattern is None
    assert rule.root_folder_header_exists is None


def test_profile_source_names_run_and_hashes():
    (profile,) = OBSERVED_PROFILES
    assert {"run", "sw1", "sw2", "operation", "date", "after_sha256", "evidence"} <= set(
        profile.source
    )
    assert profile.source["run"] == "run-sw2-_kiollnq"
    assert profile.source["after_sha256"] == S6_AFTER_SHA256


def test_catalog_of():
    assert catalog_of(REWRITE) == "observed"
    assert catalog_of(("Windows", "Bandizip")) == "paper"
