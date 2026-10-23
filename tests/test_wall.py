"""
Unit and integration tests for ai-hallucination-wall.
"""

import pytest
from pathlib import Path
from ai_hallucination_wall.core import AIHallucinationWall, Levenshtein
from ai_hallucination_wall.monetization import LicenseManager
from ai_hallucination_wall.cli import main

def test_license_manager():
    comm = LicenseManager.get_tier(None)
    assert comm["tier"] == "community"

    ent = LicenseManager.get_tier("ord_ent_wall")
    assert ent["tier"] == "enterprise"

    banner = LicenseManager.get_banner("ai-hallucination-wall")
    assert "GABFQIK63R2NETJM7T673EAMZN4RJLLGP3OFUEJU5ZVTGWUKULZJNL6" in banner

def test_levenshtein_distance():
    assert Levenshtein.distance("requests", "requests") == 0
    assert Levenshtein.distance("requests", "reqeusts") == 2
    assert Levenshtein.distance("express", "expres") == 1
    assert Levenshtein.distance("lodash", "lodesh") == 1

def test_typosquat_detection():
    rep = AIHallucinationWall.check_package("reqeusts", ecosystem="pypi")
    assert rep is not None
    assert rep.threat_type == "TYPOSQUAT"
    assert rep.matched_target == "requests"

    rep_npm = AIHallucinationWall.check_package("expres", ecosystem="npm")
    assert rep_npm is not None
    assert rep_npm.threat_type == "TYPOSQUAT"
    assert rep_npm.matched_target == "express"

def test_hallucinated_suffix_detection():
    rep = AIHallucinationWall.check_package("fastapi-official", ecosystem="pypi")
    assert rep is not None
    assert rep.threat_type == "HALLUCINATED_SLOP"

    rep_fix = AIHallucinationWall.check_package("react-helper", ecosystem="npm")
    assert rep_fix is not None
    assert rep_fix.threat_type == "HALLUCINATED_SLOP"

def test_legitimate_clean_pass():
    assert AIHallucinationWall.check_package("requests", ecosystem="pypi") is None
    assert AIHallucinationWall.check_package("react", ecosystem="npm") is None
    assert AIHallucinationWall.check_package("fastapi", ecosystem="pypi") is None

def test_inspect_command():
    bad_cmd = "pip install reqeusts"
    threats = AIHallucinationWall.inspect_command(bad_cmd)
    assert len(threats) == 1
    assert threats[0].package_name == "reqeusts"

    good_cmd = "npm install react react-dom"
    assert len(AIHallucinationWall.inspect_command(good_cmd)) == 0

def test_cli_execution(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\npydantic>=2.0\n", encoding="utf-8")

    exit_clean = main(["scan-manifest", "--file", str(req_file)])
    assert exit_clean == 0

    exit_bad = main(["check-command", "--cmd", "npm install expres"])
    assert exit_bad == 1

    exit_lic = main(["license"])
    assert exit_lic == 0
