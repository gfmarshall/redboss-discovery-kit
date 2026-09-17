import argparse
import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dk_rules import ProtectedRulesAdapter, RulesError

SENSITIVE_FIXTURE = "DO_NOT_EXPORT_SENSITIVE_VALUE"


def enabled_manifest(valid_manifest):
    manifest = json.loads(json.dumps(valid_manifest))
    manifest["dkpp"] = {
        "enabled": True,
        "profile": "eap-7.3-test",
        "extract": {"mode": "facts-only", "redaction_policy": "strict"},
        "drift_payload": {"enabled": False},
    }
    return manifest


def write_jboss_config(path: Path):
    path.write_text(
        f"""<server xmlns="urn:jboss:domain:10.0">
<profile>
  <subsystem xmlns="urn:jboss:domain:datasources:5.0">
    <datasources>
      <datasource pool-name="ExampleDS" jndi-name="java:/ExampleDS">
        <connection-url>jdbc:h2:mem:test</connection-url>
        <driver>h2</driver>
        <security><password>{SENSITIVE_FIXTURE}</password></security>
      </datasource>
    </datasources>
  </subsystem>
</profile>
</server>""",
        encoding="utf-8",
    )


@pytest.fixture
def rules_dir():
    return Path(__file__).parent / "fixtures" / "dkpp"


def test_adapter_extracts_allowlisted_facts_without_raw_config_or_secret(valid_manifest, jboss_env, rules_dir):
    manifest = enabled_manifest(valid_manifest)
    config = jboss_env["app_instance"] / "configuration" / "standalone.xml"
    write_jboss_config(config)

    facts = ProtectedRulesAdapter(rules_dir, manifest).extract(config)

    group = facts["groups"]["datasources"]
    assert group["counts"]["datasource_count"] == 1
    assert group["items"] == [
        {
            "kind": "datasource",
            "name": "ExampleDS",
            "jndi_name": "java:/ExampleDS",
            "driver": "h2",
        }
    ]
    serialized = json.dumps(facts)
    assert SENSITIVE_FIXTURE not in serialized
    assert "connection-url" not in serialized
    assert "<server" not in serialized


def test_adapter_rejects_disabled_manifest(valid_manifest, rules_dir):
    with pytest.raises(RulesError, match="explicitly enable"):
        ProtectedRulesAdapter(rules_dir, valid_manifest)


def test_adapter_rejects_pack_identity_substitution(valid_manifest, rules_dir, tmp_path):
    copied = tmp_path / "rules"
    shutil.copytree(rules_dir, copied)
    pack = json.loads((copied / "pack.json").read_text())
    pack["id"] = "untrusted-pack"
    (copied / "pack.json").write_text(json.dumps(pack))
    with pytest.raises(RulesError, match="identity is invalid"):
        ProtectedRulesAdapter(copied, enabled_manifest(valid_manifest))


def test_adapter_rejects_profile_path_traversal(valid_manifest, rules_dir):
    manifest = enabled_manifest(valid_manifest)
    manifest["dkpp"]["profile"] = "../outside"
    with pytest.raises(RulesError, match="not declared"):
        ProtectedRulesAdapter(rules_dir, manifest)


def test_adapter_rejects_sensitive_fact_field(valid_manifest, rules_dir, tmp_path):
    copied = tmp_path / "rules"
    shutil.copytree(rules_dir, copied)
    rule = copied / "xpaths" / "eap-7.3" / "datasources.xpath"
    rule.write_text('//datasource {\n    password: "password/text()"\n}\n')
    adapter = ProtectedRulesAdapter(copied, enabled_manifest(valid_manifest))
    config = tmp_path / "standalone.xml"
    write_jboss_config(config)
    with pytest.raises(RulesError, match="field name is prohibited"):
        adapter.extract(config)


def test_cmd_run_writes_schema_valid_facts_and_pack_metadata(dk_mod, valid_manifest, tmp_path, jboss_env, rules_dir):
    manifest = enabled_manifest(valid_manifest)
    config = jboss_env["app_instance"] / "configuration" / "standalone.xml"
    write_jboss_config(config)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    output = tmp_path / "evidence"
    args = argparse.Namespace(
        manifest=str(manifest_path),
        out=str(output),
        run_id="rules-contract",
        rules_dir=str(rules_dir),
        archive=True,
    )
    fake_result = MagicMock(stdout='{"bomFormat":"CycloneDX"}')

    with patch("subprocess.run", return_value=fake_result):
        assert dk_mod.cmd_run(args) == 0

    run_dir = output / "rules-contract"
    facts_path = run_dir / "app1-instance" / "facts.dkpp.json"
    assert facts_path.exists()
    facts = json.loads(facts_path.read_text())
    dk_mod.jsonschema.Draft202012Validator(dk_mod.DKPP_FACTS_SCHEMA).validate(facts)
    pack = json.loads((run_dir / "dk-pack.json").read_text())
    assert pack["dkpp"] == {
        "pack_id": "redboss-dk-plus",
        "ruleset_version": "1.0.0-test",
        "profile": "eap-7.3-test",
        "redaction_policy": "strict",
    }
    archive_bytes = (output / "rules-contract.tar.gz").read_bytes()
    assert SENSITIVE_FIXTURE.encode() not in archive_bytes


def test_cmd_run_requires_enablement_and_rules_directory(dk_mod, valid_manifest, tmp_path, rules_dir):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(valid_manifest))
    base = {
        "manifest": str(manifest_path),
        "out": str(tmp_path / "out"),
        "run_id": "mismatch",
        "archive": False,
    }

    with pytest.raises(dk_mod.DKError, match="requires both"):
        dk_mod.cmd_run(argparse.Namespace(**base, rules_dir=str(rules_dir)))

    enabled = enabled_manifest(valid_manifest)
    manifest_path.write_text(json.dumps(enabled))
    with pytest.raises(dk_mod.DKError, match="requires both"):
        dk_mod.cmd_run(argparse.Namespace(**base, rules_dir=None))
