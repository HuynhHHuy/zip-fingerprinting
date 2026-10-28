"""Multi-provenance and archive modification analyzer.

Reference:
    Minji Um et al. (2021), Section 4.2 & Figure 10:
    Tracking archive manipulations (Add, Delete, Modify) across different software.

When a second program (SW2) adds, modifies or deletes entries of an archive created by SW1,
the binary headers record it in one of two ways (Section 4.2):

* **Case 1 - mixed fingerprints:** only the manipulated entry receives SW2's headers, so a single
  archive holds entries whose host OS, extra-field types/order or ``0x5455`` lengths belong to
  different, mutually incompatible environments.
* **Case 2 - cascade rewrite:** SW2 rewrites the headers of the remaining entries (e.g. strips or
  replaces their extra fields after a deletion). When local file headers keep SW1's structure while
  central directory headers carry SW2's, the LFH/CDH pair of an entry matches no single profile.

Every entry is fingerprinted and classified independently with the existing
:class:`~zip_fingerprint.classifier.AutomatedClassifier`; nothing is decompressed. Only high-weight
structural evidence sets ``is_multi_provenance``. Subsidiary signals (nanosecond patterns) are
reported for further analysis but never treated as proof. Absence of heterogeneity does not prove
single provenance: SW2 may rewrite every header, and some catalog profiles overlap completely
(e.g. Windows 7-Zip and Bandizip for ASCII names).
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from zip_fingerprint.classifier import AutomatedClassifier
from zip_fingerprint.constants import (
    EXTRA_HEADER_EXTENDED_TS,
    EXTRA_HEADER_UNICODE_PATH,
    NANO_PATTERN_FULL,
    NANO_PATTERN_WINZIP,
)
from zip_fingerprint.extractor import StructuralFeatureExtractor
from zip_fingerprint.models import (
    CentralDirectoryHeaderRecord,
    ExtraFieldBlock,
    LocalFileHeaderRecord,
    ZipArchiveRecord,
)
from zip_fingerprint.rules import FingerprintRule, get_all_rules

Environment = Tuple[str, str]  # (target_os, application)

WEIGHT_HIGH = "HIGH"
WEIGHT_SUBSIDIARY = "SUBSIDIARY"
CASE_1 = "CASE_1"
CASE_2 = "CASE_2"
ROLE_ORIGINAL = "ORIGINAL_CREATOR_SUSPECT"
ROLE_MODIFIER = "MODIFIER_SUSPECT"
ROLE_SOLE = "SOLE_SOURCE"
SCOPE_ARCHIVE = "ARCHIVE"
SCOPE_ALL = "ALL_ENTRIES"
SCOPE_PARTIAL = "PARTIAL"


def _env_dicts(environments: List[Environment]) -> List[Dict[str, str]]:
    return [{"target_os": os_name, "application": app} for os_name, app in environments]


@dataclass
class EntryFingerprint:
    """Independent structural fingerprint of one CDH/LFH pair."""

    index: int
    file_name: str
    local_header_offset: int
    host_os: int
    data_descriptor_present: bool
    local_extra_field_sequence: List[int]
    central_extra_field_sequence: List[int]
    local_5455_length: Optional[int]
    central_5455_length: Optional[int]
    nanosecond_pattern: str
    # Every environment compatible with the full entry, in classifier ranking order.
    candidates: List[Environment] = field(default_factory=list)
    # Profiles matched by the LFH side alone and by the CDH side (with host OS) alone.
    local_side_candidates: List[Environment] = field(default_factory=list)
    central_side_candidates: List[Environment] = field(default_factory=list)
    # True when LFH and CDH match the same catalog profile variant (or the entry is
    # simply uncatalogued); False only for a Case 2 LFH/CDH discrepancy.
    lfh_cdh_consistent: bool = True

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key in ("candidates", "local_side_candidates", "central_side_candidates"):
            data[key] = _env_dicts(getattr(self, key))
        return data


@dataclass
class ProvenanceGroup:
    """Entries whose fingerprints are compatible with at least one common environment."""

    entry_names: List[str]
    candidates: List[Environment]
    host_os: int
    first_local_header_offset: int
    role: str = ROLE_SOLE
    # Central directory indices; names may repeat in tampered archives.
    entry_indices: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["candidates"] = _env_dicts(self.candidates)
        return data


@dataclass
class ProvenanceIndicator:
    """A single piece of tampering evidence."""

    code: str
    case: str
    weight: str
    entries: List[str]
    detail: str
    scope: str = SCOPE_ARCHIVE

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SuspectedApplication:
    """An environment suspected of creating or manipulating the archive."""

    target_os: str
    application: str
    role: str
    basis: str
    entries: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProvenanceReport:
    """Multi-provenance and integrity report for one archive."""

    is_multi_provenance: bool
    case1_detected: bool
    case2_detected: bool
    requires_further_analysis: bool
    groups: List[ProvenanceGroup]
    indicators: List[ProvenanceIndicator]
    suspected_applications: List[SuspectedApplication]
    inference_history: List[str]
    entries: List[EntryFingerprint]

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "is_multi_provenance": self.is_multi_provenance,
            "requires_further_analysis": self.requires_further_analysis,
            "cases": {
                "case1_mixed_fingerprints": self.case1_detected,
                "case2_cascade_rewrite": self.case2_detected,
            },
            "groups": [group.to_dict() for group in self.groups],
            "indicators": [indicator.to_dict() for indicator in self.indicators],
            "suspected_applications": [item.to_dict() for item in self.suspected_applications],
            "inference_history": list(self.inference_history),
            "entries": [entry.to_dict() for entry in self.entries],
        }


class ProvenanceTracker:
    """Detects multi-system coexistence, header tampering, and modification history."""

    def __init__(self, archive: ZipArchiveRecord):
        self.archive = archive
        self._classifier = AutomatedClassifier()

    def analyze_modifications(self) -> Dict[str, Any]:
        """Detect Case 1 (local alterations) and Case 2 (global cascade alterations)."""
        return self.analyze().to_dict()

    def analyze(self) -> ProvenanceReport:
        """Fingerprint every entry independently and infer manipulation history."""
        history: List[str] = []
        entries = [
            self._fingerprint_entry(index, cdh, lfh)
            for index, (cdh, lfh) in enumerate(self._pair_headers())
        ]
        if not entries:
            history.append("Archive has no entries; no provenance evidence is available.")
            return ProvenanceReport(False, False, False, False, [], [], [], history, [])

        history.append(
            f"Fingerprinted {len(entries)} entries independently from CDH/LFH pairs "
            "without decompression."
        )
        for entry in entries:
            history.append(self._describe_entry(entry))

        indicators: List[ProvenanceIndicator] = []
        discrepant = [entry for entry in entries if not entry.lfh_cdh_consistent]
        case2 = bool(discrepant)
        if case2:
            indicators.append(self._case2_indicator(entries, discrepant, history))

        groups = self._group_entries(entries)
        case1 = len(groups) > 1
        if case1:
            indicators.extend(self._case1_indicators(entries, groups))
            self._assign_roles(groups)
            history.append(
                f"Case 1: {len(groups)} incompatible fingerprint groups coexist in one archive "
                "(mixed fingerprints)."
            )
            history.append(
                "Role assignment is heuristic: the group owning the lowest local header offset is "
                "presumed to be the original creator (SW1) because Add operations append entries."
            )
        else:
            history.append("All entries share at least one compatible environment (one group).")

        indicators.extend(self._subsidiary_indicators(entries, groups))
        suspects = self._suspected_applications(groups, discrepant, case1)
        further = any(indicator.weight == WEIGHT_SUBSIDIARY for indicator in indicators)
        if further:
            history.append(
                "Subsidiary evidence differs between entries; further analysis required. "
                "Subsidiary signals alone do not establish multi-provenance."
            )
        multi = case1 or case2
        if not multi:
            history.append(
                "No high-weight heterogeneity found. This does not prove single provenance: SW2 "
                "may rewrite every header, or SW1/SW2 profiles may overlap."
            )
        return ProvenanceReport(
            is_multi_provenance=multi,
            case1_detected=case1,
            case2_detected=case2,
            requires_further_analysis=further,
            groups=groups,
            indicators=indicators,
            suspected_applications=suspects,
            inference_history=history,
            entries=entries,
        )

    # ------------------------------------------------------------------ entry fingerprints
    def _pair_headers(
        self,
    ) -> List[Tuple[CentralDirectoryHeaderRecord, Optional[LocalFileHeaderRecord]]]:
        by_offset = {lfh.offset: lfh for lfh in self.archive.local_file_headers}
        return [
            (cdh, by_offset.get(cdh.local_header_offset))
            for cdh in self.archive.central_directory_headers
        ]

    def _fingerprint_entry(
        self,
        index: int,
        cdh: CentralDirectoryHeaderRecord,
        lfh: Optional[LocalFileHeaderRecord],
    ) -> EntryFingerprint:
        single = ZipArchiveRecord(
            file_path=self.archive.file_path,
            file_size=self.archive.file_size,
            eocd=self.archive.eocd,
            central_directory_headers=[cdh],
            local_file_headers=[lfh] if lfh is not None else [],
        )
        features = StructuralFeatureExtractor(single).extract()
        candidates = [
            (item.target_os, item.application) for item in self._classifier.classify(features)
        ]
        local_blocks = lfh.extra_fields if lfh is not None else []
        descriptor = bool(lfh.has_data_descriptor) if lfh is not None else False
        host = (cdh.version_made_by >> 8) & 0xFF
        local_len = self._length_5455(local_blocks)
        central_len = self._length_5455(cdh.extra_fields)
        local_ids = {block.header_id for block in local_blocks}
        central_ids = {block.header_id for block in cdh.extra_fields}

        local_side: List[Environment] = []
        central_side: List[Environment] = []
        pair_match = False
        for rule in get_all_rules():
            env = (rule.target_os, rule.application)
            for variant_local, variant_central in self._variants(rule):
                local_ok = (
                    local_ids == set(variant_local)
                    and descriptor == rule.data_descriptor_required
                    and rule.extra_5455_length_local in (None, local_len)
                )
                central_ok = (
                    central_ids == set(variant_central)
                    and host == rule.host_os_code
                    and rule.extra_5455_length_central in (None, central_len)
                )
                if local_ok and env not in local_side:
                    local_side.append(env)
                if central_ok and env not in central_side:
                    central_side.append(env)
                pair_match = pair_match or (local_ok and central_ok)
        discrepancy = not pair_match and bool(local_side) and bool(central_side)

        return EntryFingerprint(
            index=index,
            file_name=cdh.file_name,
            local_header_offset=cdh.local_header_offset,
            host_os=host,
            data_descriptor_present=descriptor,
            local_extra_field_sequence=[block.header_id for block in local_blocks],
            central_extra_field_sequence=[block.header_id for block in cdh.extra_fields],
            local_5455_length=local_len,
            central_5455_length=central_len,
            nanosecond_pattern=str(features["subsidiary"]["nanosecond_pattern"]),
            candidates=candidates,
            local_side_candidates=local_side,
            central_side_candidates=central_side,
            lfh_cdh_consistent=not discrepancy,
        )

    @staticmethod
    def _variants(rule: FingerprintRule) -> Iterator[Tuple[Tuple[int, ...], Tuple[int, ...]]]:
        """Yield paired (LFH, CDH) extra-field sets: ASCII base and non-ASCII variant."""
        yield rule.local_extra_ids, rule.central_extra_ids
        if rule.local_extra_ids_unicode or rule.central_extra_ids_unicode:
            yield rule.local_extra_ids_unicode, rule.central_extra_ids_unicode

    @staticmethod
    def _length_5455(blocks: List[ExtraFieldBlock]) -> Optional[int]:
        for block in blocks:
            if block.header_id == EXTRA_HEADER_EXTENDED_TS:
                return block.data_size
        return None

    @staticmethod
    def _describe_entry(entry: EntryFingerprint) -> str:
        def hex_ids(ids: List[int]) -> str:
            return "[" + ", ".join(f"0x{value:04X}" for value in ids) + "]"

        if entry.candidates:
            verdict = "compatible with " + ", ".join(f"{o}/{a}" for o, a in entry.candidates)
        elif not entry.lfh_cdh_consistent:
            verdict = "LFH and CDH match different profiles (LFH/CDH discrepancy)"
        else:
            verdict = "matches no supported catalog profile (uncatalogued structure)"
        return (
            f"Entry '{entry.file_name}': host OS {entry.host_os}, "
            f"LFH {hex_ids(entry.local_extra_field_sequence)}, "
            f"CDH {hex_ids(entry.central_extra_field_sequence)} -> {verdict}."
        )

    # ------------------------------------------------------------------ Case 1
    @staticmethod
    def _effective_candidates(entry: EntryFingerprint) -> List[Environment]:
        """Environments used for grouping; a rewritten CDH reflects its last writer."""
        if entry.candidates:
            return entry.candidates
        if not entry.lfh_cdh_consistent:
            return entry.central_side_candidates
        return []

    @staticmethod
    def _uncatalogued_signature(entry: EntryFingerprint) -> Tuple[Any, ...]:
        """Structure of an uncatalogued entry; 0x7075 depends on the name, not the tool."""

        def strip(ids: List[int]) -> Tuple[int, ...]:
            return tuple(value for value in ids if value != EXTRA_HEADER_UNICODE_PATH)

        return (
            entry.data_descriptor_present,
            strip(entry.local_extra_field_sequence),
            strip(entry.central_extra_field_sequence),
            entry.local_5455_length,
            entry.central_5455_length,
        )

    def _group_entries(self, entries: List[EntryFingerprint]) -> List[ProvenanceGroup]:
        """Greedily merge entries (central directory order) that keep a common environment."""
        groups: List[ProvenanceGroup] = []
        signatures: List[Optional[Tuple[Any, ...]]] = []
        for entry in entries:
            effective = self._effective_candidates(entry)
            signature = None if effective else self._uncatalogued_signature(entry)
            for group, group_signature in zip(groups, signatures):
                if group.host_os != entry.host_os:
                    continue
                if effective and group.candidates:
                    common = [env for env in group.candidates if env in effective]
                    if not common:
                        continue
                    group.candidates = common
                elif effective or group.candidates or signature != group_signature:
                    continue
                group.entry_names.append(entry.file_name)
                group.entry_indices.append(entry.index)
                group.first_local_header_offset = min(
                    group.first_local_header_offset, entry.local_header_offset
                )
                break
            else:
                groups.append(
                    ProvenanceGroup(
                        entry_names=[entry.file_name],
                        candidates=list(effective),
                        host_os=entry.host_os,
                        first_local_header_offset=entry.local_header_offset,
                        entry_indices=[entry.index],
                    )
                )
                signatures.append(signature)
        return groups

    @staticmethod
    def _case1_indicators(
        entries: List[EntryFingerprint], groups: List[ProvenanceGroup]
    ) -> List[ProvenanceIndicator]:
        indicators: List[ProvenanceIndicator] = []
        hosts: Dict[int, List[str]] = {}
        for entry in entries:
            hosts.setdefault(entry.host_os, []).append(entry.file_name)
        if len(hosts) > 1:
            summary = ", ".join(f"{code} ({len(names)} entries)" for code, names in hosts.items())
            indicators.append(
                ProvenanceIndicator(
                    code="MIXED_HOST_OS",
                    case=CASE_1,
                    weight=WEIGHT_HIGH,
                    entries=[entry.file_name for entry in entries],
                    detail=f"Algorithm 2 host OS differs between entries: {summary}.",
                )
            )
        known = [group for group in groups if group.candidates]
        if len(known) > 1:
            indicators.append(
                ProvenanceIndicator(
                    code="INCOMPATIBLE_ENTRY_FINGERPRINTS",
                    case=CASE_1,
                    weight=WEIGHT_HIGH,
                    entries=[name for group in known for name in group.entry_names],
                    detail=(
                        f"{len(known)} entry groups have disjoint compatible environments "
                        "(extra-field types/order, 0x5455 lengths, descriptor or host OS)."
                    ),
                )
            )
        unknown = [group for group in groups if not group.candidates]
        if unknown:
            indicators.append(
                ProvenanceIndicator(
                    code="HETEROGENEOUS_STRUCTURE",
                    case=CASE_1,
                    weight=WEIGHT_HIGH,
                    entries=[name for group in unknown for name in group.entry_names],
                    detail="Uncatalogued entry structures differ from other entries in the archive.",
                )
            )
        return indicators

    @staticmethod
    def _assign_roles(groups: List[ProvenanceGroup]) -> None:
        original = min(groups, key=lambda group: group.first_local_header_offset)
        for group in groups:
            group.role = ROLE_ORIGINAL if group is original else ROLE_MODIFIER

    # ------------------------------------------------------------------ Case 2
    @staticmethod
    def _case2_indicator(
        entries: List[EntryFingerprint],
        discrepant: List[EntryFingerprint],
        history: List[str],
    ) -> ProvenanceIndicator:
        scope = SCOPE_ALL if len(discrepant) == len(entries) else SCOPE_PARTIAL
        names = [entry.file_name for entry in discrepant]
        if scope == SCOPE_ALL:
            history.append(
                "Case 2: every entry keeps an LFH of one profile while its CDH matches another; "
                "consistent with SW2 rewriting the central directory (e.g. after a deletion)."
            )
        else:
            history.append(
                f"Case 2: {len(discrepant)} of {len(entries)} entries show an LFH/CDH discrepancy; "
                "their central directory headers were rewritten by another program."
            )
        return ProvenanceIndicator(
            code="LFH_CDH_DISCREPANCY",
            case=CASE_2,
            weight=WEIGHT_HIGH,
            entries=names,
            detail=(
                "Local file headers match a different catalog profile than central directory "
                "headers for the same entries."
            ),
            scope=scope,
        )

    # ------------------------------------------------------------------ subsidiary
    @staticmethod
    def _subsidiary_indicators(
        entries: List[EntryFingerprint], groups: List[ProvenanceGroup]
    ) -> List[ProvenanceIndicator]:
        indicators: List[ProvenanceIndicator] = []
        for group in groups:
            members = [entries[index] for index in group.entry_indices]
            patterns = {
                entry.nanosecond_pattern
                for entry in members
                if entry.nanosecond_pattern in (NANO_PATTERN_FULL, NANO_PATTERN_WINZIP)
            }
            if len(patterns) > 1:
                indicators.append(
                    ProvenanceIndicator(
                        code="MIXED_NANOSECOND_PATTERN",
                        case=CASE_1,
                        weight=WEIGHT_SUBSIDIARY,
                        entries=[
                            entry.file_name
                            for entry in members
                            if entry.nanosecond_pattern in patterns
                        ],
                        detail=(
                            "Entries with compatible high-weight structure mix WinZip-style "
                            "'fff0000' and full 'fffffff' 0x000A nanoseconds."
                        ),
                    )
                )
        return indicators

    # ------------------------------------------------------------------ suspects
    @staticmethod
    def _suspected_applications(
        groups: List[ProvenanceGroup],
        discrepant: List[EntryFingerprint],
        case1: bool,
    ) -> List[SuspectedApplication]:
        suspects: Dict[Tuple[str, str, str, str], List[str]] = {}

        def add(env: Environment, role: str, basis: str, names: List[str]) -> None:
            bucket = suspects.setdefault((env[0], env[1], role, basis), [])
            bucket.extend(name for name in names if name not in bucket)

        if case1:
            for group in groups:
                for env in group.candidates:
                    add(env, group.role, "CASE_1:entry_group", group.entry_names)
        for entry in discrepant:
            for env in entry.local_side_candidates:
                add(env, ROLE_ORIGINAL, "CASE_2:local_file_header", [entry.file_name])
            for env in entry.central_side_candidates:
                add(env, ROLE_MODIFIER, "CASE_2:central_directory_header", [entry.file_name])
        if not case1 and not discrepant:
            seen: Set[Environment] = set()
            for group in groups:
                for env in group.candidates:
                    if env not in seen:
                        seen.add(env)
                        add(env, ROLE_SOLE, "SINGLE_GROUP", group.entry_names)
        return [
            SuspectedApplication(target_os=o, application=a, role=r, basis=b, entries=names)
            for (o, a, r, b), names in suspects.items()
        ]
