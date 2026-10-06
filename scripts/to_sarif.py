#!/usr/bin/env python3
"""
Переводит отчёты DAST-инструментов в SARIF для вкладки GitHub Security.

  python3 scripts/to_sarif.py nuclei nuclei.jsonl nuclei.sarif
  python3 scripts/to_sarif.py dastardly dastardly-report.xml dastardly.sarif

GitHub требует, чтобы каждая находка была привязана к файлу в репозитории.
DAST-находки относятся к адресам (URL), поэтому привязываем их к app/app.py,
а сам адрес пишем в текст находки.
"""
import json
import re
import sys

ANCHOR_FILE = "app/app.py"

# Уровень опасности -> уровень SARIF и числовая оценка для GitHub
SEVERITY = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.5"),
    "low": ("note", "3.0"),
    "info": ("note", "1.0"),
    "information": ("note", "1.0"),
}


def level_and_score(severity):
    return SEVERITY.get(str(severity).lower(), ("note", "1.0"))


def read_nuclei(path):
    """Каждая строка JSONL — одна находка Nuclei."""
    findings = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            info = r.get("info", {})
            findings.append({
                "rule_id": r.get("template-id", "nuclei-finding"),
                "name": info.get("name", "Nuclei finding"),
                "severity": info.get("severity", "info"),
                "description": info.get("description", ""),
                "url": r.get("matched-at", r.get("host", "")),
            })
    return findings


def read_dastardly(path):
    """JUnit XML: каждый testcase с failure — одна находка.
    Разбираем регулярными выражениями: в отчётах Dastardly бывают
    символы, на которых строгий XML-парсер падает."""
    text = open(path, encoding="utf-8", errors="replace").read()
    pattern = re.compile(
        r'<testcase name="([^"]+)">\s*<failure message="([^"]*)" type="(\w+)">'
        r"<!\[CDATA\[(.*?)\]\]>",
        re.S,
    )
    findings = []
    for name, message, severity, body in pattern.findall(text):
        path_match = re.search(r"Path: (\S+)", body)
        findings.append({
            "rule_id": "dastardly-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-"),
            "name": name,
            "severity": severity,
            "description": message,
            "url": path_match.group(1) if path_match else "",
        })
    return findings


def to_sarif(tool_name, findings):
    rules, results, seen = [], [], set()
    for f in findings:
        level, score = level_and_score(f["severity"])
        if f["rule_id"] not in seen:
            seen.add(f["rule_id"])
            rules.append({
                "id": f["rule_id"],
                "name": f["name"],
                "shortDescription": {"text": f["name"]},
                "fullDescription": {"text": f["description"] or f["name"]},
                "properties": {"security-severity": score, "tags": ["security", "dast"]},
            })
        results.append({
            "ruleId": f["rule_id"],
            "level": level,
            "message": {"text": f"{f['name']} — найдено по адресу: {f['url']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": ANCHOR_FILE},
                    "region": {"startLine": 1},
                }
            }],
            # Разные URL -> разные отпечатки, чтобы GitHub не склеивал их в одну
            "partialFingerprints": {"dastUrl": f"{f['rule_id']}|{f['url']}"},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "rules": rules}},
            "results": results,
        }],
    }


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("nuclei", "dastardly"):
        sys.exit(__doc__)
    kind, src, dst = sys.argv[1:]
    try:
        findings = read_nuclei(src) if kind == "nuclei" else read_dastardly(src)
    except FileNotFoundError:
        print(f"Файл {src} не найден — считаем, что находок нет")
        findings = []
    sarif = to_sarif("Nuclei" if kind == "nuclei" else "Dastardly", findings)
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)
    print(f"{kind}: {len(findings)} находок -> {dst}")


if __name__ == "__main__":
    main()
