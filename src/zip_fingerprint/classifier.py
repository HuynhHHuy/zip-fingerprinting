"""Automated provenance classifier implementing Algorithm 1, 2, and 3.

Reference:
    Minji Um et al. (2021), Figure 7 (Flowchart) and Figure 8 (Algorithms 1, 2, 3).
"""

from typing import Any, Dict, List, Optional, Tuple

from zip_fingerprint.constants import EXTRA_HEADER_EXTENDED_TS
from zip_fingerprint.models import CandidateEnvironment
from zip_fingerprint.rules import FingerprintRule, get_all_rules


class AutomatedClassifier:
    """Classifies creation OS and application using hierarchical weighted rules."""

    def classify(self, features: Dict[str, Any]) -> List[CandidateEnvironment]:
        """Return compatible environments, retaining ambiguity rather than guessing.

        HIGH/1.0 means a unique match within the empirical catalog, not a
        guarantee of provenance. SUBSIDIARY scores are heuristic evidence scores,
        not calibrated probabilities. Unknown or mixed structures return [].
        """
        if features.get("summary", {}).get("total_entries") == 0:
            return []
        operating_systems = self.estimate_program_2(features)
        candidates = [
            rule
            for rule in self.estimate_program_1(features)
            if rule.target_os in operating_systems
        ]
        if len(candidates) == 1:
            rule = candidates[0]
            return [
                CandidateEnvironment(
                    target_os=rule.target_os,
                    application=rule.application,
                    confidence=1.0,
                    matched_rules=self._high_weight_matches(rule),
                    weight_tier="HIGH",
                    notes=["Unique structural/OS match within the supported empirical catalog."],
                )
            ]
        return self.estimate_program_3(features, candidates)

    def estimate_program_1(self, features: Dict[str, Any]) -> List[FingerprintRule]:
        """Algorithm 1: match descriptor, LFH/CDH field types and 0x5455 lengths.

        Compare field sets here, preserving header order as subsidiary evidence.
        Match ASCII and Unicode variants as pairs, not independently per header.
        """
        high = features.get("high_weight", {})
        if not isinstance(high, dict) or not isinstance(high.get("data_descriptor_present"), bool):
            return []
        for key in ("local_extra_field_ids", "central_extra_field_ids"):
            values = high.get(key)
            if not isinstance(values, list) or any(type(value) is not int for value in values):
                return []

        local = set(high["local_extra_field_ids"])
        central = set(high["central_extra_field_ids"])
        candidates = []
        for rule in get_all_rules():
            if high["data_descriptor_present"] != rule.data_descriptor_required:
                continue
            variants = [(rule.local_extra_ids, rule.central_extra_ids)]
            if rule.local_extra_ids_unicode or rule.central_extra_ids_unicode:
                variants.append((rule.local_extra_ids_unicode, rule.central_extra_ids_unicode))
            if not any(local == set(lfh) and central == set(cdh) for lfh, cdh in variants):
                continue
            if not self._matches_length(
                high, "local_extra_field_lengths", rule.extra_5455_length_local
            ):
                continue
            if not self._matches_length(
                high, "central_extra_field_lengths", rule.extra_5455_length_central
            ):
                continue
            candidates.append(rule)
        return candidates

    def estimate_program_2(self, features: Dict[str, Any]) -> List[str]:
        """Algorithm 2: decode the creating-version host byte without guessing UNIX OS."""
        high = features.get("high_weight", {})
        if not isinstance(high, dict) or high.get("has_consistent_host_os", True) is not True:
            return []
        host = high.get("host_os")
        if isinstance(host, bool) or not isinstance(host, int):
            return []
        return {0: ["Windows"], 3: ["macOS", "Ubuntu"]}.get(host, [])

    def estimate_program_3(
        self, features: Dict[str, Any], candidates: List[FingerprintRule]
    ) -> List[CandidateEnvironment]:
        """Algorithm 3: rank every compatible candidate with low-weight evidence.

        The paper collects subsidiary signals but supplies no numeric weights.
        This project's policy uses weights 3 for field variants/order/nanoseconds/UID/nested ZIP,
        2 for normalization/encoding/__MACOSX and 1 for folder/order conventions.
        Agreement and disagreement contribute symmetrically about 0.5; the
        range [0.01, 0.99] deliberately never claims high-tier certainty.
        """
        results = []
        for rule in candidates:
            matched = self._high_weight_matches(rule)
            notes = ["Heuristic evidence score; not a calibrated probability."]
            balance = total_weight = 0
            for name, observed, expected, weight in self._subsidiary_evidence(features, rule):
                total_weight += weight
                if observed == expected:
                    balance += weight
                    matched.append(f"algorithm3:{name}={observed}")
                else:
                    balance -= weight
                    notes.append(f"Conflicting {name}: observed {observed}, expected {expected}.")
            confidence = round(0.5 + 0.49 * balance / total_weight, 6) if total_weight else 0.5
            if not total_weight:
                notes.append("No comparable subsidiary evidence; further analysis required.")
            results.append(
                CandidateEnvironment(
                    target_os=rule.target_os,
                    application=rule.application,
                    confidence=confidence,
                    matched_rules=matched,
                    weight_tier="SUBSIDIARY",
                    notes=notes,
                )
            )
        results.sort(key=lambda item: (-item.confidence, item.target_os, item.application))
        if len(results) > 1 and results[0].confidence == results[1].confidence:
            for candidate in results:
                if candidate.confidence == results[0].confidence:
                    candidate.notes.append(
                        "Ambiguous top-ranked environments; further analysis required."
                    )
        return results

    @staticmethod
    def _matches_length(high: Dict[str, Any], key: str, expected: Optional[int]) -> bool:
        if expected is None:
            return True
        lengths = high.get(key, {})
        if not isinstance(lengths, dict):
            return False
        # JSON converts integer object keys to decimal strings.
        values = lengths.get(EXTRA_HEADER_EXTENDED_TS, lengths.get(str(EXTRA_HEADER_EXTENDED_TS)))
        return (
            isinstance(values, list) and bool(values) and all(value == expected for value in values)
        )

    @staticmethod
    def _high_weight_matches(rule: FingerprintRule) -> List[str]:
        matches = [
            "algorithm1:data_descriptor_present",
            "algorithm1:local_extra_field_ids",
            "algorithm1:central_extra_field_ids",
            f"algorithm2:host_os={rule.host_os_code}",
        ]
        if rule.extra_5455_length_local is not None:
            matches.extend(["algorithm1:local_0x5455_length", "algorithm1:central_0x5455_length"])
        return matches

    @staticmethod
    def _subsidiary_evidence(
        features: Dict[str, Any], rule: FingerprintRule
    ) -> List[Tuple[str, Any, Any, int]]:
        high = features.get("high_weight", {})
        sub = features.get("subsidiary", {})
        evidence: List[Tuple[str, Any, Any, int]] = []
        sequence = high.get("central_extra_field_sequence")
        if isinstance(sequence, list) and sequence:
            expected_order = tuple(item for item in rule.central_extra_sequence if item in sequence)
            evidence.append(("central_extra_field_sequence", tuple(sequence), expected_order, 3))
        pattern = sub.get("nanosecond_pattern")
        if pattern in ("fff0000", "fffffff", "0000000") and rule.nanosecond_pattern is not None:
            evidence.append(("nanosecond_pattern", pattern, rule.nanosecond_pattern, 3))
        normalization = sub.get("unicode_normalization")
        if normalization in ("NFC", "NFD") and rule.unicode_normalization is not None:
            evidence.append(("unicode_normalization", normalization, rule.unicode_normalization, 2))
            # The extractor emits ASCII separately, so NFC/NFD also indicates
            # non-ASCII names. Missing 0x7075 then favors Windows 7-Zip, but
            # this target-dependent signal must not manufacture a HIGH match.
            has_variant = bool(rule.local_extra_ids_unicode or rule.central_extra_ids_unicode)
            local_ids = rule.local_extra_ids_unicode if has_variant else rule.local_extra_ids
            central_ids = rule.central_extra_ids_unicode if has_variant else rule.central_extra_ids
            observed_fields = (
                tuple(sorted(high["local_extra_field_ids"])),
                tuple(sorted(high["central_extra_field_ids"])),
            )
            expected_fields = (tuple(sorted(local_ids)), tuple(sorted(central_ids)))
            evidence.append(("unicode_extra_field_variant", observed_fields, expected_fields, 3))
        if sub.get("filename_encoding") == "CP949":
            expected_encoding = "CP949" if rule.target_os == "Windows" else "UTF-8"
            evidence.append(("filename_encoding", "CP949", expected_encoding, 2))
        uid, gid = sub.get("uid"), sub.get("gid")
        if uid is not None and gid is not None and rule.default_uid_gid is not None:
            evidence.append(("uid_gid", (uid, gid), rule.default_uid_gid, 3))
        nested = sub.get("double_zipping")
        if nested in ("STORED", "RECOMPRESSED") and rule.double_zipping_behavior is not None:
            evidence.append(
                ("double_zipping", nested == "RECOMPRESSED", rule.double_zipping_behavior, 3)
            )
        for key, expected, weight in (
            ("has_macosx_folder", rule.has_macosx_folder, 2),
            ("root_folder_header_exists", rule.root_folder_header_exists, 1),
            ("is_alphabetical_order", rule.is_alphabetical_order, 1),
        ):
            value = sub.get(key)
            if isinstance(value, bool) and expected is not None:
                evidence.append((key, value, expected, weight))
        return evidence
