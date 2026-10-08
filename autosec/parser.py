import json
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class VulnerabilityFinding:
    rule_id: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    snippet: Optional[str] = None
    cwe: Optional[str] = None

def parse_sarif_or_json(content_or_path: str) -> List[VulnerabilityFinding]:
    """Parse SARIF v2.1.0 or generic SAST JSON finding report."""
    try:
        with open(content_or_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, OSError):
        data = json.loads(content_or_path)

    findings: List[VulnerabilityFinding] = []

    # Standard SARIF v2.1.0 format
    if "runs" in data:
        for run in data.get("runs", []):
            rules_map = {}
            driver = run.get("tool", {}).get("driver", {})
            for r in driver.get("rules", []):
                r_id = r.get("id")
                cwe_tag = None
                tags = r.get("properties", {}).get("tags", [])
                for tag in tags:
                    if "CWE" in tag or "cwe" in tag:
                        cwe_tag = tag
                        break
                rules_map[r_id] = cwe_tag

            for res in run.get("results", []):
                rule_id = res.get("ruleId", "UNKNOWN_RULE")
                msg = res.get("message", {}).get("text", "")
                locations = res.get("locations", [])
                file_path = ""
                start_line = 1
                end_line = 1
                snippet = None

                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    file_path = phys.get("artifactLocation", {}).get("uri", "")
                    r_region = phys.get("region", {})
                    start_line = r_region.get("startLine", 1)
                    end_line = r_region.get("endLine", start_line)
                    snippet = r_region.get("snippet", {}).get("text")

                findings.append(
                    VulnerabilityFinding(
                        rule_id=rule_id,
                        message=msg,
                        file_path=file_path.replace("file://", "").lstrip("./"),
                        start_line=start_line,
                        end_line=end_line,
                        snippet=snippet,
                        cwe=rules_map.get(rule_id),
                    )
                )
    # Generic simple JSON format: {"findings": [...]}
    elif "findings" in data:
        for item in data.get("findings", []):
            findings.append(
                VulnerabilityFinding(
                    rule_id=item.get("rule_id", "SECURITY_ISSUE"),
                    message=item.get("message", ""),
                    file_path=item.get("file_path", "").lstrip("./"),
                    start_line=item.get("start_line", 1),
                    end_line=item.get("end_line", 1),
                    snippet=item.get("snippet"),
                    cwe=item.get("cwe"),
                )
            )

    return findings
