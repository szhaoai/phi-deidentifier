 

"""
PHI/PII De-identifier Module

Production-grade de-identification pipeline for sensitive data (PII/PHI).
Default behavior is REDACTION for all detected entities unless explicitly overridden.
"""

import re
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib


class EntityType(Enum):
    """Supported entity types for detection."""
    PERSON_NAME = "PERSON_NAME"
    DATE = "DATE"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    ADDRESS = "ADDRESS"
    SSN = "SSN"
    MRN = "MRN"
    PASSPORT = "PASSPORT"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    LOCATION = "LOCATION"
    MEDICAL_RECORD = "MEDICAL_RECORD"
    INSURANCE_ID = "INSURANCE_ID"
    VEHICLE_ID = "VEHICLE_ID"
    DEVICE_ID = "DEVICE_ID"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    ORGANIZATION = "ORGANIZATION"
    USERNAME = "USERNAME"
    PASSWORD = "PASSWORD"
    API_KEY = "API_KEY"
    GENERIC_PII = "GENERIC_PII"


class Severity(Enum):
    """Severity levels for entities."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Action(Enum):
    """Transformation actions."""
    REDACT = "REDACT"
    MASK = "MASK"
    HASH = "HASH"
    TOKENIZE = "TOKENIZE"
    KEEP = "KEEP"


class Mode(Enum):
    """De-identification mode."""
    SAFE_HARBOR = "SAFE_HARBOR"
    RISK_BASED = "RISK_BASED"


class Policy(Enum):
    """De-identification policy."""
    HIPAA = "HIPAA"
    GENERAL_PII = "GENERIC_PII"
    CUSTOM = "CUSTOM"


ENTITY_COLORS = {
    EntityType.PERSON_NAME.value: "#FFE082",
    EntityType.DATE.value: "#4DB6AC",
    EntityType.PHONE.value: "#CE93D8",
    EntityType.EMAIL.value: "#CE93D8",
    EntityType.ADDRESS.value: "#81C784",
    EntityType.SSN.value: "#EF5350",
    EntityType.MRN.value: "#EF5350",
    EntityType.PASSPORT.value: "#EF5350",
    EntityType.CREDIT_CARD.value: "#EF5350",
    EntityType.IP_ADDRESS.value: "#EF5350",
    EntityType.LOCATION.value: "#81C784",
    EntityType.MEDICAL_RECORD.value: "#EF5350",
    EntityType.INSURANCE_ID.value: "#EF5350",
    EntityType.VEHICLE_ID.value: "#FFB74D",
    EntityType.DEVICE_ID.value: "#90CAF9",
    EntityType.BANK_ACCOUNT.value: "#EF5350",
    EntityType.ORGANIZATION.value: "#F48FB1",
    EntityType.USERNAME.value: "#B39DDB",
    EntityType.PASSWORD.value: "#FF5722",
    EntityType.API_KEY.value: "#FF5722",
    EntityType.GENERIC_PII.value: "#BDBDBD",
}


@dataclass
class Entity:
    """Represents a detected entity."""
    entity_id: str
    entity_type: str
    start: int
    end: int
    confidence: float
    severity: str
    action: str
    replacement: str = ""
    provenance: List[str] = field(default_factory=list)
    notes: str = "No raw value recorded."


@dataclass
class DeidentifyRequest:
    """Request configuration for de-identification."""
    mode: str = "SAFE_HARBOR"
    policy: str = "HIPAA"
    default_action: str = "REDACT"
    reversible: bool = False
    locale: str = "en-US"
    timestamp_iso: str = ""


class PIIRegexPatterns:
    """Regex patterns for PII detection."""
    SSN = re.compile(
        r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
        re.IGNORECASE,
    )
    PHONE = re.compile(
        r'\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b'
    )
    EMAIL = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        re.IGNORECASE,
    )
    IP_ADDRESS = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    CREDIT_CARD = re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|'
        r'5[1-5][0-9]{14}|'
        r'3[47][0-9]{13}|'
        r'6(?:011|5[0-9]{2})[0-9]{12}|'
        r'(?:2131|1800|35\d{3})\d{11})\b'
    )
    PASSPORT = re.compile(r'\b[0-9]{9}\b')
    DATE = re.compile(
        r'\b(?:(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12][0-9]|3[01])[/-](?:19|20)?\d{2}|'
        r'(?:19|20)?\d{2}[/-](?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12][0-9]|3[01]))\b'
    )
    DATE_VERBAL = re.compile(
        r'\b(?:January|February|March|April|May|June|July|August|September|October|'
        r'November|December)\s+\d{1,2},?\s+\d{4}\b',
        re.IGNORECASE,
    )
    PERSON_NAME_TITLE = re.compile(
        r'\b(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Doctor)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b'
    )
    # Fallback pattern for names without title prefixes (First Last format)
    PERSON_NAME_BASIC = re.compile(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b')
    MRN = re.compile(
        r'\b(?:MRN|mrn|Medical\s*Record\s*[#]?\s*)[:#]?\s*([A-Z0-9-]{5,15})\b',
        re.IGNORECASE,
    )
    INSURANCE_ID = re.compile(
        r'\b(?:Policy|Policy\s*#|Member\s*ID|Insurance|Insurance\s*ID)[:#]?\s*'
        r'([A-Z0-9-]{6,12})\b',
        re.IGNORECASE,
    )
    VIN = re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b')
    DEVICE_ID = re.compile(
        r'\b(?:Device|Device\s*ID)[:#]?\s*([A-Fa-f0-9-]{8,36})\b',
        re.IGNORECASE,
    )
    BANK_ACCOUNT = re.compile(
        r'\b(?:Account|Account\s*#|Account\s*Number|Bank|Bank\s*Account)[:#]?\s*'
        r'([0-9]{8,17})\b',
        re.IGNORECASE,
    )
    API_KEY = re.compile(
        r'\b(?:api[_-]?key|apikey|token|auth[_-]?token|access[_-]?key)[=:]\s*'
        r'([A-Za-z0-9_\-]{20,})\b',
        re.IGNORECASE,
    )
    PASSWORD = re.compile(
        r'\b(?:password|passwd|pwd)[=:]\s*([^\s]{4,})\b',
        re.IGNORECASE,
    )
    ADDRESS = re.compile(
        r'\b\d{1,5}\s+(?:[A-Za-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|'
        r'Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\.?\b',
        re.IGNORECASE,
    )


class PIIRulesEngine:
    """Rule-based PII detection engine."""
    def __init__(self):
        self.compiled_patterns = {
            EntityType.SSN.value: (PIIRegexPatterns.SSN, 0.95, Severity.HIGH.value),
            EntityType.PHONE.value: (PIIRegexPatterns.PHONE, 0.85, Severity.MEDIUM.value),
            EntityType.EMAIL.value: (PIIRegexPatterns.EMAIL, 0.90, Severity.MEDIUM.value),
            EntityType.IP_ADDRESS.value: (PIIRegexPatterns.IP_ADDRESS, 0.85, Severity.MEDIUM.value),
            EntityType.CREDIT_CARD.value: (PIIRegexPatterns.CREDIT_CARD, 0.90, Severity.HIGH.value),
            EntityType.PASSPORT.value: (PIIRegexPatterns.PASSPORT, 0.85, Severity.HIGH.value),
            EntityType.DATE.value: (PIIRegexPatterns.DATE, 0.80, Severity.LOW.value),
            EntityType.MRN.value: (PIIRegexPatterns.MRN, 0.85, Severity.HIGH.value),
            EntityType.INSURANCE_ID.value: (PIIRegexPatterns.INSURANCE_ID, 0.80, Severity.HIGH.value),
            EntityType.VEHICLE_ID.value: (PIIRegexPatterns.VIN, 0.85, Severity.MEDIUM.value),
            EntityType.DEVICE_ID.value: (PIIRegexPatterns.DEVICE_ID, 0.80, Severity.MEDIUM.value),
            EntityType.BANK_ACCOUNT.value: (PIIRegexPatterns.BANK_ACCOUNT, 0.80, Severity.HIGH.value),
            EntityType.API_KEY.value: (PIIRegexPatterns.API_KEY, 0.85, Severity.HIGH.value),
            EntityType.PASSWORD.value: (PIIRegexPatterns.PASSWORD, 0.90, Severity.HIGH.value),
            EntityType.ADDRESS.value: (PIIRegexPatterns.ADDRESS, 0.75, Severity.MEDIUM.value),
        }
        self.date_patterns = [
            (PIIRegexPatterns.DATE, 0.80, Severity.LOW.value),
            (PIIRegexPatterns.DATE_VERBAL, 0.80, Severity.LOW.value),
        ]

    def detect(self, text: str) -> List[Entity]:
        entities = []
        entity_counter = 1

        # Core patterns
        for entity_type, (pattern, base_confidence, severity) in self.compiled_patterns.items():
            for match in pattern.finditer(text):
                start, end = match.span()
                if match.lastindex:
                    group_span = match.span(match.lastindex)
                    if group_span[1] > group_span[0]:
                        start, end = group_span
                entity = Entity(
                    entity_id=f"E{entity_counter}",
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    confidence=base_confidence,
                    severity=severity,
                    action=Action.REDACT.value,
                    provenance=["regex"],
                )
                entities.append(entity)
                entity_counter += 1

        # Date patterns (numeric and verbal)
        for pattern, base_confidence, severity in self.date_patterns:
            for match in pattern.finditer(text):
                start, end = match.span()
                entity = Entity(
                    entity_id=f"E{entity_counter}",
                    entity_type=EntityType.DATE.value,
                    start=start,
                    end=end,
                    confidence=base_confidence,
                    severity=severity,
                    action=Action.REDACT.value,
                    provenance=["regex"],
                )
                entities.append(entity)
                entity_counter += 1

        # Title-prefixed person names
        for match in PIIRegexPatterns.PERSON_NAME_TITLE.finditer(text):
            start, end = match.span()
            entity = Entity(
                entity_id=f"E{entity_counter}",
                entity_type=EntityType.PERSON_NAME.value,
                start=start,
                end=end,
                confidence=0.95,
                severity=Severity.HIGH.value,
                action=Action.REDACT.value,
                provenance=["regex_title"],
            )
            entities.append(entity)
            entity_counter += 1

        # Basic person names (First Last)
        for match in PIIRegexPatterns.PERSON_NAME_BASIC.finditer(text):
            start, end = match.span()
            entity = Entity(
                entity_id=f"E{entity_counter}",
                entity_type=EntityType.PERSON_NAME.value,
                start=start,
                end=end,
                confidence=0.70,
                severity=Severity.HIGH.value,
                action=Action.REDACT.value,
                provenance=["regex_basic"],
            )
            entities.append(entity)
            entity_counter += 1

        return entities


class PIIHybridDetector:
    """Hybrid PII detection combining rules + NER."""
    def __init__(self, use_ner: bool = True):
        self.rules_engine = PIIRulesEngine()
        self.ner_available = False
        self.nlp = None
        self.use_ner = use_ner
        self._init_error = None  # Add this line
        self._init_ner()
 
    def _init_ner(self):
        try:
            import spacy
            # Try medical, then large, then small general English models
            attempted_models = []
            last_error = None
            
            for model_name in ["en_core_med_lg", "en_core_web_lg", "en_core_web_sm"]:
                try:
                    self.nlp = spacy.load(model_name)
                    self.ner_available = True
                    return
                except Exception as e:
                    attempted_models.append(model_name)
                    last_error = str(e)
                    continue
            
            # If all fail, log the issue
            self.nlp = None
            self.ner_available = False
            
            # Store error for debugging
            self._init_error = (
                f"Failed to load any spaCy model. Tried: {attempted_models}. "
                f"Last error: {last_error}"
            )
            
        except ImportError as e:
            self.nlp = None
            self.ner_available = False
            self._init_error = f"spaCy import failed: {str(e)}"
        except Exception as e:
            self.nlp = None
            self.ner_available = False
            self._init_error = f"Unexpected error during NER init: {str(e)}"

    def detect(self, text: str) -> List[Entity]:
        entities = self.rules_engine.detect(text)
        if self.use_ner and self.ner_available and self.nlp:
            entities.extend(self._detect_with_ner(text))
        return entities

    def _detect_with_ner(self, text: str) -> List[Entity]:
        entities = []
        entity_counter = 1000
        doc = self.nlp(text)
        for ent in doc.ents:
            if ent.label_ == "PERSON":
                entity = Entity(
                    entity_id=f"E{entity_counter}",
                    entity_type=EntityType.PERSON_NAME.value,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=0.80,
                    severity=Severity.HIGH.value,
                    action=Action.REDACT.value,
                    provenance=["ner"],
                )
                entities.append(entity)
                entity_counter += 1
            elif ent.label_ in ("GPE", "LOC"):
                entity = Entity(
                    entity_id=f"E{entity_counter}",
                    entity_type=EntityType.LOCATION.value,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=0.75,
                    severity=Severity.MEDIUM.value,
                    action=Action.REDACT.value,
                    provenance=["ner"],
                )
                entities.append(entity)
                entity_counter += 1
        return entities


class SpanOverlapResolver:
    """Resolves overlapping entity spans."""
    @staticmethod
    def resolve(entities: List[Entity]) -> List[Entity]:
        if not entities:
            return []

        def sort_by_priority(ent: Entity) -> Tuple:
            severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
            length = ent.end - ent.start
            return (-length, ent.confidence, severity_order.get(ent.severity, 0))

        sorted_entities = sorted(entities, key=sort_by_priority)

        resolved: List[Entity] = []
        for entity in sorted_entities:
            overlaps = False
            for existing in resolved:
                if entity.start < existing.end and entity.end > existing.start:
                    overlaps = True
                    break
            if not overlaps:
                resolved.append(entity)

        return resolved


class TextTransformer:
    """Transforms text based on entity actions."""
    @staticmethod
    def transform(text: str, entities: List[Entity], reversible: bool = False) -> str:
        if not entities:
            return text
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        result = text
        for entity in sorted_entities:
            if entity.action == Action.REDACT.value:
                replacement = "[REDACTED]"
            elif entity.action == Action.MASK.value:
                val = text[entity.start:entity.end]
                replacement = (
                    val[0] + "*" * (len(val) - 2) + val[-1]
                    if len(val) > 2
                    else "*" * len(val)
                )
            elif entity.action == Action.HASH.value:
                replacement = hashlib.sha256(
                    text[entity.start:entity.end].encode()
                ).hexdigest()[:16]
            elif entity.action == Action.TOKENIZE.value:
                replacement = f"[{entity.entity_type}]"
            else:
                replacement = ""
            result = result[:entity.start] + replacement + result[entity.end:]
        return result


class Deidentifier:
    """Main de-identification pipeline."""
    def __init__(self, config: Optional[DeidentifyRequest] = None):
        self.config = config or DeidentifyRequest()
        self.detector = PIIHybridDetector(use_ner=True)

    def deidentify(self, text: str) -> Dict[str, Any]:
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        request = {
            "mode": self.config.mode,
            "policy": self.config.policy,
            "default_action": self.config.default_action,
            "reversible": self.config.reversible,
            "locale": self.config.locale,
            "timestamp_iso": timestamp,
        }

        all_entities = self.detector.detect(text)
        entities = SpanOverlapResolver.resolve(all_entities)
        deidentified_text = TextTransformer.transform(
            text, entities, self.config.reversible
        )

        review_required = any(
            e.severity == Severity.HIGH.value and e.action != Action.REDACT.value
            for e in entities
        )

        highlights = []
        for entity in entities:
            color = ENTITY_COLORS.get(entity.entity_type, "#BDBDBD")
            highlights.append(
                {
                    "entity_id": entity.entity_id,
                    "entity_type": entity.entity_type,
                    "start": entity.start,
                    "end": entity.end,
                    "confidence": entity.confidence,
                    "severity": entity.severity,
                    "action": entity.action,
                    "color": color,
                    "tooltip": (
                        f"{entity.entity_type} • {entity.action} • "
                        f"conf={entity.confidence:.2f}"
                    ),
                }
            )

        entity_list = []
        for entity in entities:
            entity_list.append(
                {
                    "entity_id": entity.entity_id,
                    "type": entity.entity_type,
                    "start": entity.start,
                    "end": entity.end,
                    "confidence": entity.confidence,
                    "severity": entity.severity,
                    "action": entity.action,
                    "replacement": entity.replacement,
                    "provenance": entity.provenance,
                    "notes": entity.notes,
                }
            )

        return {
            "request": request,
            "result": {
                "original_text_length": len(text),
                "deidentified_text": deidentified_text,
                "summary": {
                    "entities_found": len(entities),
                    "entities_transformed": len(entities),
                    "review_required": review_required,
                },
                "highlights": highlights,
                "entities": entity_list,
                "risks": [],
                "errors": [],
            },
        }


# Reusable global deidentifier so Streamlit can inspect NER status
_global_deidentifier: Optional[Deidentifier] = None


def get_global_deidentifier() -> Deidentifier:
    """Return a singleton Deidentifier instance."""
    global _global_deidentifier
    if _global_deidentifier is None:
        _global_deidentifier = Deidentifier()
    return _global_deidentifier


def deidentify(
    text: str,
    mode: str = "SAFE_HARBOR",
    policy: str = "HIPAA",
    default_action: str = "REDACT",
    reversible: bool = False,
) -> Dict[str, Any]:
    """Convenience function for de-identification."""
    deidentifier = get_global_deidentifier()
    # Update config for this call (simple override)
    deidentifier.config.mode = mode
    deidentifier.config.policy = policy
    deidentifier.config.default_action = default_action
    deidentifier.config.reversible = reversible
    return deidentifier.deidentify(text)


if __name__ == "__main__":
    sample = (
        "Patient John Smith (SSN: 123-45-6789) visited on 01/15/2024. "
        "Contact: [john.smith@email.com](mailto:john.smith@email.com), "
        "Phone: 555-123-4567."
    )
    result = deidentify(sample)
    print(json.dumps(result, indent=2))
