"""Deterministic extraction of entity facts from the canonical event envelope.

Only fields present in NormalizedEvent or explicitly recognized source attributes
are promoted. Relationships produced here are direct observations; inference is
an explicit, separately recorded operation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

_ENTITY_TYPE_ALIASES = {
    "host": "hostname",
    "hostname": "hostname",
    "user": "user",
    "process": "process",
    "ip": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "network": "ip",
    "domain": "domain",
    "file": "file",
    "file_hash": "file_hash",
}
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


@dataclass(frozen=True, slots=True)
class EntityFact:
    entity_type: str
    normalized_value: str
    display_value: str
    entity_id: str


@dataclass(frozen=True, slots=True)
class RelationshipFact:
    source_entity_id: str
    target_entity_id: str
    relationship_type: str
    evidence_kind: str = "OBSERVED"
    confidence: float = 1.0


def normalize_entity_type(entity_type: str) -> str:
    """Normalize supported aliases to the canonical entity taxonomy."""
    value = entity_type.strip().casefold()
    if value not in _ENTITY_TYPE_ALIASES:
        raise ValueError(f"Unsupported entity type: {entity_type!r}")
    return _ENTITY_TYPE_ALIASES[value]


def normalize_entity_value(entity_type: str, value: str) -> str:
    """Return the stable lookup key for a supported entity type."""
    canonical_type = normalize_entity_type(entity_type)
    if not isinstance(value, str):
        raise ValueError("Entity value must be a string.")
    text = value.strip()
    if not text or len(text) > 512:
        raise ValueError("Entity value must contain between 1 and 512 characters.")
    if canonical_type == "ip":
        return ipaddress.ip_address(text).compressed
    if canonical_type == "domain":
        domain = text.rstrip(".").encode("idna").decode("ascii").casefold()
        if len(domain) > 253 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in domain.split(".")
        ):
            raise ValueError("Invalid domain entity value.")
        return domain
    if canonical_type == "file":
        return text.replace("\\", "/").casefold()
    if canonical_type == "file_hash":
        algorithm, separator, digest = text.partition(":")
        algorithm = algorithm.casefold()
        digest = digest.casefold()
        if not separator or algorithm not in _HASH_LENGTHS:
            raise ValueError("File hash must use md5:, sha1:, or sha256: notation.")
        if len(digest) != _HASH_LENGTHS[algorithm] or not re.fullmatch(r"[0-9a-f]+", digest):
            raise ValueError("File hash digest has an invalid length or encoding.")
        return f"{algorithm}:{digest}"
    return text.casefold()


def entity_identifier(entity_type: str, normalized_value: str) -> str:
    """Create a stable opaque identifier for an entity identity."""
    material = f"{entity_type}\\0{normalized_value}".encode()
    return hashlib.sha256(material).hexdigest()


def _text(value: object, *, maximum: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if candidate and len(candidate) <= maximum else None


def _attribute(attributes: dict[str, object], *names: str) -> object | None:
    wanted = {name.casefold() for name in names}
    for key, value in attributes.items():
        if isinstance(key, str) and key.casefold() in wanted:
            return value
    return None


def _nested(attributes: dict[str, object], group: str, *names: str) -> object | None:
    value = _attribute(attributes, group)
    if not isinstance(value, dict):
        return None
    return _attribute(value, *names)


def _domain(value: object) -> str | None:
    candidate = _text(value, maximum=253)
    if candidate is None:
        return None
    try:
        return normalize_entity_value("domain", candidate)
    except (UnicodeError, ValueError):
        return None


def _ip(value: object) -> str | None:
    candidate = _text(value, maximum=64)
    if candidate is None:
        return None
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return None


def _process_identity(
    hostname: str | None,
    *,
    guid: object | None = None,
    pid: object | None = None,
    name: object | None = None,
) -> tuple[str, str] | None:
    guid_text = _text(guid, maximum=128)
    name_text = _text(name, maximum=256)
    pid_text = str(pid).strip() if isinstance(pid, (int, str)) and not isinstance(pid, bool) else ""
    if pid_text and not pid_text.isdigit():
        pid_text = ""
    if guid_text:
        identity = f"guid:{guid_text.casefold()}"
    elif pid_text:
        identity = f"pid:{pid_text}"
    elif name_text:
        identity = f"name:{name_text.casefold()}"
    else:
        return None
    host_prefix = f"{hostname.casefold()}|" if hostname else ""
    return f"{host_prefix}{identity}", name_text or (f"pid:{pid_text}" if pid_text else identity)


def extract_event_observations(
    event: dict[str, object],
) -> tuple[tuple[EntityFact, ...], tuple[RelationshipFact, ...]]:
    """Extract bounded entity and direct relationship facts from one event."""
    if not isinstance(event, dict):
        raise ValueError("Normalized event payload must be an object.")
    event_id = _text(event.get("event_id"), maximum=64)
    timestamp = _text(event.get("timestamp"), maximum=64)
    source_type = _text(event.get("source_type"), maximum=128)
    event_type = _text(event.get("event_type"), maximum=128)
    if not all((event_id, timestamp, source_type, event_type)):
        raise ValueError("Normalized event identity, timestamp, and source fields are required.")

    raw_attributes = event.get("attributes")
    attributes = raw_attributes if isinstance(raw_attributes, dict) else {}
    entities: dict[tuple[str, str], EntityFact] = {}
    relationships: dict[tuple[str, str, str, str], RelationshipFact] = {}

    def add_entity(entity_type: str, raw_value: object, display_value: object | None = None) -> EntityFact | None:
        text_value = _text(raw_value)
        if text_value is None:
            return None
        try:
            normalized = normalize_entity_value(entity_type, text_value)
            canonical_type = normalize_entity_type(entity_type)
        except (UnicodeError, ValueError):
            return None
        key = (canonical_type, normalized)
        fact = entities.get(key)
        if fact is None:
            display = _text(display_value) or text_value
            fact = EntityFact(
                entity_type=canonical_type,
                normalized_value=normalized,
                display_value=display[:512],
                entity_id=entity_identifier(canonical_type, normalized),
            )
            entities[key] = fact
        return fact

    def add_relationship(
        source: EntityFact | None,
        target: EntityFact | None,
        relationship_type: str,
    ) -> None:
        if source is None or target is None or source.entity_id == target.entity_id:
            return
        relation = relationship_type.upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", relation):
            return
        key = (source.entity_id, target.entity_id, relation, "OBSERVED")
        relationships[key] = RelationshipFact(
            source_entity_id=source.entity_id,
            target_entity_id=target.entity_id,
            relationship_type=relation,
        )

    hostname_raw = _text(event.get("hostname"), maximum=255)
    host = add_entity("hostname", hostname_raw) if hostname_raw else None
    username = add_entity("user", event.get("username"))
    src_ip = add_entity("ip", _ip(event.get("src_ip")))
    dst_ip = add_entity("ip", _ip(event.get("dst_ip")))

    process_name = _text(event.get("process_name"), maximum=256)
    process_pid = event.get("pid")
    process_guid = _attribute(attributes, "ProcessGuid", "process_guid")
    process_identity = _process_identity(
        hostname_raw,
        guid=process_guid,
        pid=process_pid,
        name=process_name,
    )
    process = (
        add_entity("process", process_identity[0], process_identity[1])
        if process_identity is not None
        else None
    )

    add_relationship(host, username, "HAS_USER")
    add_relationship(host, process, "RUNS_PROCESS")
    add_relationship(username, process, "EXECUTES_PROCESS")
    add_relationship(process, dst_ip, "CONNECTS_TO")
    add_relationship(host, dst_ip, "COMMUNICATES_WITH")
    add_relationship(src_ip, dst_ip, "COMMUNICATES_WITH")

    domains: list[EntityFact] = []
    for raw_domain in (
        _nested(attributes, "dns", "rrname", "query"),
        _nested(attributes, "http", "hostname"),
        _nested(attributes, "tls", "sni"),
        _attribute(attributes, "domain", "dns_query", "query"),
    ):
        domain_value = _domain(raw_domain)
        if domain_value:
            fact = add_entity("domain", domain_value)
            if fact is not None and fact not in domains:
                domains.append(fact)
                add_relationship(process, fact, "CONTACTS_DOMAIN")
                add_relationship(host, fact, "CONTACTS_DOMAIN")

    dns_answers = _nested(attributes, "dns", "answers")
    if isinstance(dns_answers, list):
        for answer in dns_answers[:100]:
            answer_ip = _ip(answer.get("answer") if isinstance(answer, dict) else answer)
            answer_fact = add_entity("ip", answer_ip)
            for domain_fact in domains:
                add_relationship(domain_fact, answer_fact, "RESOLVES_TO")

    file_info = _attribute(attributes, "fileinfo")
    file_name = (
        _attribute(file_info, "filename", "name")
        if isinstance(file_info, dict)
        else None
    )
    if file_name is None:
        file_name = _attribute(attributes, "file_path", "TargetFilename", "FileName")
    if file_name is None and process_name and ("\\" in process_name or "/" in process_name):
        file_name = process_name
    file_fact = add_entity("file", file_name)
    add_relationship(process, file_fact, "EXECUTES_FILE")
    add_relationship(host, file_fact, "OBSERVED_FILE")

    hashes: list[EntityFact] = []
    for algorithm in _HASH_LENGTHS:
        raw_hash = (
            _attribute(file_info, algorithm)
            if isinstance(file_info, dict)
            else None
        )
        if raw_hash is None:
            raw_hash = _attribute(attributes, algorithm, f"{algorithm}_hash")
        if isinstance(raw_hash, str):
            try:
                hash_fact = add_entity("file_hash", f"{algorithm}:{raw_hash}")
            except ValueError:
                hash_fact = None
            if hash_fact is not None and hash_fact not in hashes:
                hashes.append(hash_fact)

    raw_hashes = _attribute(attributes, "Hashes", "hashes")
    if isinstance(raw_hashes, str):
        for item in raw_hashes.split(";")[:8]:
            algorithm, separator, digest = item.partition("=")
            if separator:
                try:
                    hash_fact = add_entity("file_hash", f"{algorithm.strip()}:{digest.strip()}")
                except ValueError:
                    hash_fact = None
                if hash_fact is not None and hash_fact not in hashes:
                    hashes.append(hash_fact)

    for hash_fact in hashes:
        add_relationship(file_fact, hash_fact, "HAS_HASH")

    parent_guid = _attribute(attributes, "ParentProcessGuid", "parent_process_guid")
    parent_pid = _attribute(attributes, "ParentProcessId", "ParentProcessID", "parent_pid")
    parent_name = _attribute(attributes, "ParentImage", "parent_process_name", "parent_image")
    parent_identity = _process_identity(
        hostname_raw,
        guid=parent_guid,
        pid=parent_pid,
        name=parent_name,
    )
    parent_process = (
        add_entity("process", parent_identity[0], parent_identity[1])
        if parent_identity is not None
        else None
    )
    add_relationship(parent_process, process, "PARENT_OF")

    return tuple(entities.values()), tuple(relationships.values())


__all__ = [
    "EntityFact",
    "RelationshipFact",
    "entity_identifier",
    "extract_event_observations",
    "normalize_entity_type",
    "normalize_entity_value",
]
