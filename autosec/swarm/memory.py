from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
import time

@dataclass
class MemoryRecord:
    memory_id: str
    cwe: str
    pattern_signature: str
    successful_patch_strategy: str
    exploit_payload_signature: str
    confidence: float
    timestamp: float = field(default_factory=time.time)

class EpisodicSwarmMemory:
    """Persistent working memory for the multi-agent swarm to learn from past patch cycles."""

    def __init__(self):
        self.memory_store: Dict[str, MemoryRecord] = {}

    def remember(
        self,
        cwe: str,
        pattern_signature: str,
        successful_patch_strategy: str,
        exploit_payload_signature: str,
        confidence: float = 0.95
    ) -> str:
        mem_id = f"mem_{cwe}_{int(time.time() * 1000)}"
        record = MemoryRecord(
            memory_id=mem_id,
            cwe=cwe,
            pattern_signature=pattern_signature,
            successful_patch_strategy=successful_patch_strategy,
            exploit_payload_signature=exploit_payload_signature,
            confidence=confidence,
        )
        self.memory_store[mem_id] = record
        return mem_id

    def recall_similar_fix(self, cwe: str) -> Optional[MemoryRecord]:
        """Retrieve highest confidence past successful remediation for the CWE."""
        matching = [r for r in self.memory_store.values() if r.cwe == cwe]
        if not matching:
            return None
        return sorted(matching, key=lambda r: r.confidence, reverse=True)[0]

    def dump_knowledge_graph(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": r.memory_id,
                "cwe": r.cwe,
                "strategy": r.successful_patch_strategy,
                "confidence": r.confidence,
            }
            for r in self.memory_store.values()
        ]
