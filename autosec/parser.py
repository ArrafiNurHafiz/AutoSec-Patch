import json
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


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
    """Parse SARIF v2.1.0 or generic SAST JSON finding report with strict schema validation."""
    if not content_or_path or not isinstance(content_or_path, str):
        return []

    data = None
    if os.path.isfile(content_or_path):
        try:
            with open(content_or_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.warning(
                "Failed to read/parse SARIF file '%s': %s", content_or_path, e
            )
            return []
    else:
        try:
            data = json.loads(content_or_path)
        except (json.JSONDecodeError, TypeError, ValueError):
            return []

    findings: List[VulnerabilityFinding] = []

    # Standard SARIF v2.1.0 format
    if isinstance(data, dict) and "runs" in data:
        runs = data.get("runs")
        if isinstance(runs, list):
            for run in runs:
                if not isinstance(run, dict):
                    continue

                rules_map = {}
                tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
                driver = (
                    tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
                )
                rules = (
                    driver.get("rules") if isinstance(driver.get("rules"), list) else []
                )

                for r in rules:
                    if not isinstance(r, dict):
                        continue
                    r_id = r.get("id")
                    if not isinstance(r_id, str):
                        continue
                    cwe_tag = None
                    properties = (
                        r.get("properties")
                        if isinstance(r.get("properties"), dict)
                        else {}
                    )
                    tags = (
                        properties.get("tags")
                        if isinstance(properties.get("tags"), list)
                        else []
                    )
                    for tag in tags:
                        if isinstance(tag, str) and "cwe" in tag.lower():
                            cwe_tag = tag.strip()
                            break
                    rules_map[r_id] = cwe_tag

                results = (
                    run.get("results") if isinstance(run.get("results"), list) else []
                )
                for res in results:
                    if not isinstance(res, dict):
                        continue

                    rule_id = str(res.get("ruleId") or "UNKNOWN_RULE")
                    msg_obj = res.get("message")
                    if isinstance(msg_obj, dict):
                        msg = str(msg_obj.get("text") or "")
                    elif isinstance(msg_obj, str):
                        msg = msg_obj
                    else:
                        msg = ""

                    locations = (
                        res.get("locations")
                        if isinstance(res.get("locations"), list)
                        else []
                    )
                    file_path = ""
                    start_line = 1
                    end_line = 1
                    snippet = None

                    if locations and isinstance(locations[0], dict):
                        phys = (
                            locations[0].get("physicalLocation")
                            if isinstance(locations[0].get("physicalLocation"), dict)
                            else {}
                        )
                        art_loc = (
                            phys.get("artifactLocation")
                            if isinstance(phys.get("artifactLocation"), dict)
                            else {}
                        )
                        raw_uri = art_loc.get("uri")
                        if isinstance(raw_uri, str):
                            file_path = raw_uri.replace("file://", "").lstrip("./")

                        r_region = (
                            phys.get("region")
                            if isinstance(phys.get("region"), dict)
                            else {}
                        )
                        try:
                            start_line = int(r_region.get("startLine", 1))
                            if start_line < 1:
                                start_line = 1
                        except (ValueError, TypeError):
                            start_line = 1

                        try:
                            end_line = int(r_region.get("endLine", start_line))
                            if end_line < start_line:
                                end_line = start_line
                        except (ValueError, TypeError):
                            end_line = start_line

                        snip = (
                            r_region.get("snippet")
                            if isinstance(r_region.get("snippet"), dict)
                            else {}
                        )
                        if isinstance(snip.get("text"), str):
                            snippet = snip.get("text")

                    cwe = rules_map.get(rule_id)
                    if not cwe:
                        props = (
                            res.get("properties")
                            if isinstance(res.get("properties"), dict)
                            else {}
                        )
                        tags = (
                            props.get("tags")
                            if isinstance(props.get("tags"), list)
                            else []
                        )
                        for tag in tags:
                            if isinstance(tag, str) and "cwe" in tag.lower():
                                cwe = tag.strip()
                                break

                    findings.append(
                        VulnerabilityFinding(
                            rule_id=rule_id,
                            message=msg,
                            file_path=file_path,
                            start_line=start_line,
                            end_line=end_line,
                            snippet=snippet,
                            cwe=cwe,
                        )
                    )

    # Generic simple JSON format: {"findings": [...]} or list of dicts
    elif (
        isinstance(data, dict)
        and "findings" in data
        and isinstance(data.get("findings"), list)
    ):
        for item in data.get("findings", []):
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("rule_id") or item.get("ruleId") or "SECURITY_ISSUE")
            message = str(item.get("message") or "")
            raw_path = item.get("file_path") or item.get("filePath") or ""
            file_path = str(raw_path).replace("file://", "").lstrip("./")
            try:
                start_line = int(item.get("start_line", item.get("startLine", 1)))
                if start_line < 1:
                    start_line = 1
            except (ValueError, TypeError):
                start_line = 1

            try:
                end_line = int(item.get("end_line", item.get("endLine", start_line)))
                if end_line < start_line:
                    end_line = start_line
            except (ValueError, TypeError):
                end_line = start_line

            snippet = item.get("snippet")
            if snippet is not None and not isinstance(snippet, str):
                snippet = str(snippet)
            cwe = item.get("cwe")
            if cwe is not None and not isinstance(cwe, str):
                cwe = str(cwe)

            findings.append(
                VulnerabilityFinding(
                    rule_id=rule_id,
                    message=message,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=snippet,
                    cwe=cwe,
                )
            )
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("rule_id") or item.get("ruleId") or "SECURITY_ISSUE")
            message = str(item.get("message") or "")
            raw_path = item.get("file_path") or item.get("filePath") or ""
            file_path = str(raw_path).replace("file://", "").lstrip("./")
            try:
                start_line = int(item.get("start_line", item.get("startLine", 1)))
                if start_line < 1:
                    start_line = 1
            except (ValueError, TypeError):
                start_line = 1
            try:
                end_line = int(item.get("end_line", item.get("endLine", start_line)))
                if end_line < start_line:
                    end_line = start_line
            except (ValueError, TypeError):
                end_line = start_line

            snippet = item.get("snippet")
            if snippet is not None and not isinstance(snippet, str):
                snippet = str(snippet)
            cwe = item.get("cwe")
            if cwe is not None and not isinstance(cwe, str):
                cwe = str(cwe)

            findings.append(
                VulnerabilityFinding(
                    rule_id=rule_id,
                    message=message,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=snippet,
                    cwe=cwe,
                )
            )

    return findings
