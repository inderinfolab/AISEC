"""Renders every NexaGuard field exercise through Streamlit's AppTest and checks key behaviours."""
import os
import pytest
from streamlit.testing.v1 import AppTest
import ex_part1, ex_part2, ex_part3, ex_part4  # noqa: F401
import range_core as R

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")
SECTION = {1: "Field exercises: Part 1 Foundations", 2: "Field exercises: Part 2 Attacks",
           3: "Field exercises: Part 3 Defenses", 4: "Field exercises: Part 4 Cloud & MLOps"}


def open_ex(ex_id):
    part = R.REG[ex_id].part
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.radio(key="section").set_value(SECTION[part]).run()
    at.radio(key=f"ex_{part}").set_value(ex_id).run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def ok(at):
    assert not at.exception, [e.value for e in at.exception]
    return at


@pytest.mark.parametrize("ex_id", list(R.REG))
def test_every_exercise_renders(ex_id):
    at = open_ex(ex_id)
    assert at.title and ex_id in at.title[0].value


def test_registry_counts():
    assert len(R.REG) == 34
    assert all(e.quiz and e.hints and e.tasks for e in R.REG.values())
    for e in R.REG.values():
        for q, opts, ans, why in e.quiz:
            assert 0 <= ans < len(opts) and why


def test_progress_page():
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.radio(key="section").set_value("Progress & report").run()
    ok(at)


def test_61_normalisation_reduces_evasion():
    at = open_ex("6.1")
    at.radio(key="x61_g").set_value("blocklist").run()
    m1 = at.metric[0].value
    at.radio(key="x61_g").set_value("semantic+normalize").run()
    m2 = at.metric[0].value
    assert int(m1.split("/")[0]) > int(m2.split("/")[0])


def test_62_poisoned_titan_then_defended():
    at = open_ex("6.2")
    at.multiselect(key="x62_docs").set_value(["kb-001", "doc-003-poisoned"])
    at.text_input(key="x62_q").set_value("Summarise Project Titan status").run()
    at.button(key="x62_go").click().run()
    assert any("data exfil" in e.value for e in ok(at).error)
    at.checkbox(key="x62_egress_allowlist").check().run()
    at.button(key="x62_go").click().run()
    assert not any("data exfil" in e.value for e in ok(at).error)


def test_81_defences_neutralise_poison():
    at = open_ex("8.1")
    at.checkbox(key="x81_h").check()
    at.checkbox(key="x81_p").check().run()
    assert any("neutralised" in s.value for s in ok(at).success)


def test_82_monitoring_default_detects():
    at = open_ex("8.2")
    assert any("detected" in s.value for s in ok(at).success)


def test_101_chain_best_rules():
    at = open_ex("10.1")
    from ng import CHAIN
    for n, _, truth in CHAIN:
        at.multiselect(key=f"x101_{n}").set_value([sorted(truth)[0]])
    at.multiselect(key="x101_rules").set_value(["R1", "R4"]).run()
    assert any("no false positives" in s.value for s in ok(at).success)
    at.multiselect(key="x101_rules").set_value(["R1", "R4", "R3"]).run()
    assert not any("no false positives" in s.value for s in ok(at).success)


def test_103_cascade():
    at = open_ex("10.3")
    assert any("Cascade succeeded" in e.value for e in ok(at).error)
    at.checkbox(key="x103_e").check().run()
    assert any("stopped" in s.value for s in ok(at).success)


def test_112_backdoor_detected():
    at = open_ex("11.2")
    at.multiselect(key="x112_s").set_value(["special partnership"]).run()
    at.button(key="x112_go").click().run()
    assert any("Reject the model" in s.value for s in ok(at).success)


def test_113_gate_approve():
    at = open_ex("11.3")
    for k in ("x113_s", "x113_o", "x113_l"):
        at.checkbox(key=k).check()
    at.run()
    assert any("APPROVE" in s.value for s in ok(at).success)


def test_121_123_campaign_and_risk():
    at = open_ex("12.1")
    assert at.metric and "%" in at.metric[0].value
    at = open_ex("12.3")
    assert any(m.label == "Composite risk score" for m in ok(at).metric)


def test_122_custom_attack():
    at = open_ex("12.2")
    at.button(key="x122_go").click().run()
    ok(at)


def test_141_142_143():
    at = open_ex("14.1")
    at.multiselect(key="x141_l").set_value(["structural", "content", "semantic"]).run()
    assert "88" in ok(at).metric[0].value
    at = open_ex("14.2")
    for k in ("x142_p", "x142_s", "x142_l"):
        at.checkbox(key=k).check()
    at.run()
    assert any("Pipeline complete" in s.value for s in ok(at).success)
    at = open_ex("14.3")
    at.radio(key="x143_m").set_value("strict").run()
    assert any("Perfect" in s.value for s in ok(at).success)


def test_151_hardening_target():
    at = open_ex("15.1")
    for t in ("hierarchy", "sandwich", "meta", "signed", "fewshot", "compression"):
        at.checkbox(key=f"x151_{t}").check()
    at.run()
    assert any("Target met" in s.value for s in ok(at).success)


def test_161_163():
    at = open_ex("16.1")
    assert any("Balanced" in s.value for s in ok(at).success) is False  # default weighted mode is not balanced
    at.radio(key="x161_m").set_value("any").run()
    assert any("Balanced" in s.value for s in ok(at).success)
    at = open_ex("16.3")
    at.selectbox(key="x163_high").set_value("approve")
    at.selectbox(key="x163_critical").set_value("escalate").run()
    ok(at)
    at.slider(key="x163_t").set_value(0.8).run()
    assert any("Safe and workable" in s.value for s in ok(at).success)


def test_171_supply_chain_decisions():
    at = open_ex("17.1")
    from defenses import reference_decision, audit_requirements, REQUIREMENTS
    for f in audit_requirements(REQUIREMENTS):
        at.radio(key=f"x171_{f['package']}").set_value(reference_decision(f["package"]))
    at.run()
    assert any("All decisions" in s.value for s in ok(at).success)


def test_173_tenant_namespace():
    at = open_ex("17.3")
    at.radio(key="x173_m").set_value("namespace").run()
    assert any("Isolation holds" in s.value for s in ok(at).success)
    at.radio(key="x173_m").set_value("prompt").run()
    assert not any("Isolation holds" in s.value for s in ok(at).success)


def test_181_182_183():
    at = open_ex("18.1")
    at.checkbox(key="x181_h").check()
    for k in [c.key for c in at.checkbox if c.key.startswith("x181_app_") and c.key.endswith("t")]:
        at.checkbox(key=k).check()
    at.run()
    ok(at)
    at = open_ex("18.2")
    ok(at)
    at = open_ex("18.3")
    for k in ("capability_tokens", "goal_validation", "egress_allowlist", "trace_monitoring"):
        at.checkbox(key=f"x183_{k}").check()
    at.run()
    assert any("stopped and detected" in s.value for s in ok(at).success)


def test_201_terraform_fix_flow():
    at = open_ex("20.1")
    assert at.metric[0].value == "10"
    at.multiselect(key="x201_pick").set_value([f"{p}-{n}" for p, n in [("IAM", 1)]]).run()
    at.multiselect(key="x201_pick").set_value(["IAM-1", "SM-1", "SM-2", "SM-3", "SM-4", "SM-5", "S3-1", "S3-2", "S3-3", "S3-4"]).run()
    at.button(key="x201_apply").click().run()
    assert any("Clean scan" in s.value for s in ok(at).success)


def test_202_203_hardened():
    at = open_ex("20.2")
    at.button(key="x202_sec").click().run()
    assert any("secure baseline" in s.value for s in ok(at).success)
    at = open_ex("20.3")
    at.button(key="x203_sec").click().run()
    assert any("passes the audit" in s.value for s in ok(at).success)


def test_quiz_scoring():
    at = open_ex("4.1")
    at.radio(key="q_4.1_0").set_value("Blocklists are one signal, never the control")
    at.radio(key="q_4.1_1").set_value("Blocking an analyst asking how to ignore false positives")
    at.button(key="qc_4.1").click().run()
    assert len(ok(at).success) >= 2
