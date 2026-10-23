"""
Security guardrail inspecting autonomous AI coding agent tool invocations, blocking hallucinated or typosquatted npm/PyPI dependencies.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple

# Vetted high-volume legitimate packages in Python and JavaScript ecosystems
VETTED_PYPI_PACKAGES = {
    "requests", "urllib3", "pydantic", "fastapi", "flask", "django", "sqlalchemy",
    "numpy", "pandas", "pytest", "scipy", "scikit-learn", "torch", "tensorflow",
    "transformers", "httpx", "aiohttp", "click", "rich", "boto3", "cryptography",
    "paramiko", "celery", "redis", "pillow", "jinja2", "starlette", "uvicorn",
    "alembic", "tenacity", "beautifulsoup4", "black", "ruff", "mypy", "psycopg2"
}

VETTED_NPM_PACKAGES = {
    "react", "react-dom", "next", "vue", "express", "lodash", "axios", "typescript",
    "tailwind", "tailwindcss", "postcss", "eslint", "prettier", "jest", "vitest",
    "webpack", "vite", "zod", "prisma", "@prisma/client", "rxjs", "moment", "dayjs",
    "dotenv", "cors", "morgan", "jsonwebtoken", "bcrypt", "uuid", "chalk", "commander"
}

@dataclass
class ThreatReport:
    package_name: str
    ecosystem: str  # pypi, npm
    threat_type: str  # TYPOSQUAT, HALLUCINATED_SLOP, SUSPICIOUS_AFFIX
    severity: str  # CRITICAL, HIGH
    matched_target: Optional[str]
    message: str
    remediation: str

class Levenshtein:
    @staticmethod
    def distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return Levenshtein.distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

class AIHallucinationWall:
    HALLUCINATED_SUFFIXES = [
        "-official", "-helper", "-fix", "-fixed", "-patch", "-utils-v2",
        "-core-v2", "-secure", "-fork", "-enhanced", "-client-v2"
    ]

    @classmethod
    def check_package(cls, package_name: str, ecosystem: str = "auto") -> Optional[ThreatReport]:
        pkg = package_name.strip().lower()
        if not pkg:
            return None

        # Clean version specifiers like ==1.0, >=2.0, @^18.0 preserving @scoped/names
        if pkg.startswith("@"):
            scope_and_rest = pkg[1:]
            if "/" in scope_and_rest:
                scope, rest = scope_and_rest.split("/", 1)
                pkg_core = re.split(r"[><=@~]", rest)[0].strip()
                pkg = f"@{scope}/{pkg_core}"
            else:
                pkg = re.split(r"[><=@~]", scope_and_rest)[0].strip()
        else:
            pkg = re.split(r"[><=@~]", pkg)[0].strip()

        if not pkg:
            return None

        # Check against both or specific ecosystem
        is_pypi = ecosystem in {"pypi", "auto"}
        is_npm = ecosystem in {"npm", "auto"}

        # 1. Exact match with vetted packages -> SAFE
        if (is_pypi and pkg in VETTED_PYPI_PACKAGES) or (is_npm and pkg in VETTED_NPM_PACKAGES):
            return None

        # 2. Check for Hallucinated Slop affixes (e.g. requests-official, fastapi-fix)
        vetted_pool = set()
        if is_pypi:
            vetted_pool.update(VETTED_PYPI_PACKAGES)
        if is_npm:
            vetted_pool.update(VETTED_NPM_PACKAGES)

        # For scoped packages like @types/foo, also inspect inner target
        sub_target = pkg.split("/")[-1] if "/" in pkg else pkg

        for base_pkg in vetted_pool:
            for suffix in cls.HALLUCINATED_SUFFIXES:
                if sub_target == f"{base_pkg}{suffix}":
                    return ThreatReport(
                        package_name=pkg,
                        ecosystem="pypi" if base_pkg in VETTED_PYPI_PACKAGES else "npm",
                        threat_type="HALLUCINATED_SLOP",
                        severity="CRITICAL",
                        matched_target=base_pkg,
                        message=f"Autonomous agent hallucinated package '{pkg}'. Attackers register this to hijack AI agents.",
                        remediation=f"Block installation. Use the legitimate vetted package '{base_pkg}' instead."
                    )

        # 3. Check Typosquatting / Levenshtein distance 1 or 2
        for legitimate in vetted_pool:
            if len(legitimate) >= 4 and len(sub_target) >= 4:
                dist = Levenshtein.distance(sub_target, legitimate)
                if dist in {1, 2} and sub_target != legitimate:
                    return ThreatReport(
                        package_name=pkg,
                        ecosystem="pypi" if legitimate in VETTED_PYPI_PACKAGES else "npm",
                        threat_type="TYPOSQUAT",
                        severity="CRITICAL",
                        matched_target=legitimate,
                        message=f"Possible typosquatted dependency '{pkg}' (Levenshtein distance {dist} from legitimate '{legitimate}').",
                        remediation=f"Block installation. Install '{legitimate}' instead."
                    )

        return None

    @classmethod
    def inspect_command(cls, command_str: str) -> List[ThreatReport]:
        threats: List[ThreatReport] = []
        clean = command_str.strip()

        # pip / pip3 / poetry install or add
        if re.search(r"\b(pip|pip3|poetry)\s+(install|add)\b", clean):
            parts = clean.split()
            idx = 0
            for i, p in enumerate(parts):
                if p in {"install", "add"}:
                    idx = i + 1
                    break
            pkgs = []
            skip_next = False
            for p in parts[idx:]:
                if skip_next:
                    skip_next = False
                    continue
                if p in {"-r", "-f", "-c", "--requirement", "--constraint"}:
                    skip_next = True
                    continue
                if p.startswith("-") or p in {".", "./"}:
                    continue
                pkgs.append(p)

            for p in pkgs:
                report = cls.check_package(p, ecosystem="pypi")
                if report:
                    threats.append(report)

        # npm / yarn / pnpm / bun add / install
        elif re.search(r"\b(npm\s+i|npm\s+install|npm\s+add|yarn\s+add|pnpm\s+add|bun\s+add)\b", clean):
            parts = clean.split()
            idx = 0
            for i, p in enumerate(parts):
                if p in {"i", "install", "add"}:
                    idx = i + 1
                    break
            pkgs = [p for p in parts[idx:] if not p.startswith("-") and p not in {".", "./"}]
            for p in pkgs:
                report = cls.check_package(p, ecosystem="npm")
                if report:
                    threats.append(report)

        return threats

    @classmethod
    def scan_manifest(cls, file_path: str) -> List[ThreatReport]:
        threats: List[ThreatReport] = []
        p = Path(file_path)
        if not p.exists():
            return threats

        content = p.read_text(encoding="utf-8", errors="ignore")
        if p.name.endswith(".txt") or "requirements" in p.name:
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg = re.split(r"[><=@~]", line)[0].strip()
                rep = cls.check_package(pkg, ecosystem="pypi")
                if rep:
                    threats.append(rep)
        elif p.name == "package.json":
            try:
                data = json.loads(content)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for pkg in deps.keys():
                    rep = cls.check_package(pkg, ecosystem="npm")
                    if rep:
                        threats.append(rep)
            except Exception:
                pass

        return threats
