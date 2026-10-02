"""Part 4 - Cloud & MLOps (chapter 20): Terraform audit, Kubernetes hardening and ML pipeline supply-chain audit."""
from __future__ import annotations

import json

import streamlit as st
import yaml

import defenses as D
import infra as I
from range_core import mark, register, tbl

REPO = "PacktPublishing/AI-Under-Attack"


def _load(key: str, text: str) -> None:
    st.session_state[key] = text


@register(id="20.1", part=4, title="Auditing cloud AI platform configuration (Terraform)",
          scenario="NexaGuard's SageMaker stack was deployed by a data-science team: full-access IAM role, internet-exposed notebook with root, unencrypted model and training bucket. Ghost audits it Checkov-style and applies fixes.",
          objectives=["Find IAM, encryption, network and logging gaps", "Apply fixes and verify with a re-scan"],
          tasks=["Review the insecure Terraform", "Scan", "Select findings to fix and re-scan", "Reach zero findings"],
          hints=["Start with HIGH findings: IAM over-permission, no KMS, internet access, no private subnet.", "Training-data buckets need versioning to recover from poisoning."],
          deeper=f"Real Checkov runs against SageMaker, Vertex AI and Azure ML samples: `{REPO}/Part-4/chapter-20/exercise-01`. This lab's rule engine is a small teaching subset.",
          quiz=[("Which finding enables model/data theft from the notebook most directly?", ["Missing logging", "Internet access plus root plus full-access role", "No versioning", "Large instance"], 1, "A reachable, privileged notebook is a pivot to training data and models.")])
def ex_tf():
    if "x201_tf" not in st.session_state:
        st.session_state["x201_tf"] = I.INSECURE_TF
    st.text_area("Terraform (editable)", key="x201_tf", height=260)
    f = I.scan_tf(st.session_state["x201_tf"])
    tbl(f or [{"id": "-", "severity": "-", "finding": "No findings"}])
    ids = [x["id"] for x in f]
    pick = st.multiselect("Apply recommended fixes for:", ids, key="x201_pick")
    c = st.columns(2)
    c[0].button("Apply selected fixes", key="x201_apply", on_click=lambda: _load("x201_tf", I.fix_tf(st.session_state["x201_tf"], st.session_state.get("x201_pick", []))))
    c[1].button("Reset to insecure baseline", key="x201_reset", on_click=lambda: _load("x201_tf", I.INSECURE_TF))
    st.metric("Open findings", len(f))
    if not f:
        st.success("Clean scan.")
        mark("20.1")


@register(id="20.2", part=4, title="Kubernetes security for ML workloads",
          scenario="The inference Deployment runs privileged as root with hostPath mounts, plaintext API keys and no resource limits on a GPU node. Ghost scores it Kubesec-style and hardens to Pod Security Standards.",
          objectives=["Spot ML-specific gaps (GPU access, secrets, privileges)", "Reach a secure score"],
          tasks=["Score the insecure manifest", "Load the hardened manifest", "Verify the score and open findings"],
          hints=["Secrets belong in secretKeyRefs; images should be pinned by digest.", "Always set GPU/memory limits to avoid noisy-neighbour DoS."],
          deeper=f"Real Kubesec: `{REPO}/Part-4/chapter-20/exercise-02` (`insecure_inference_deployment.yaml`, `secure_inference_deployment.yaml`).",
          quiz=[("Why is hostPath dangerous for an inference pod?", ["Slow disk", "Exposes the node filesystem and credentials", "Needs GPU", "Larger images"], 1, "A compromised model server could read kubelet credentials or other pods' data.")])
def ex_k8s():
    if "x202_y" not in st.session_state:
        st.session_state["x202_y"] = I.INSECURE_K8S
    st.text_area("Deployment manifest (editable)", key="x202_y", height=300)
    c = st.columns(2)
    c[0].button("Load hardened manifest", key="x202_sec", on_click=lambda: _load("x202_y", I.SECURE_K8S))
    c[1].button("Reset to insecure", key="x202_ins", on_click=lambda: _load("x202_y", I.INSECURE_K8S))
    try:
        f, score = I.k8s_findings(st.session_state["x202_y"])
    except Exception as e:
        st.error(f"Invalid manifest: {e}")
        return
    st.metric("Kubesec-style score", score)
    tbl(f or [{"severity": "-", "points": 0, "finding": "none"}])
    if score >= 10 and not [x for x in f if x["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]:
        st.success("Meets the secure baseline.")
        mark("20.2")


@register(id="20.3", part=4, title="MLOps pipeline security audit",
          scenario="The training pipeline hard-codes AWS keys, installs from an HTTP index, pipes curl into bash, downloads an unpinned model, saves pickle and signs nothing. Ghost audits it, fixes it and generates an SBOM.",
          objectives=["Audit pipeline supply-chain risk", "Fix credential handling and pinning", "Produce SBOM and signing"],
          tasks=["Audit the insecure pipeline and the unpinned requirements", "Load the secure pipeline", "Confirm zero findings"],
          hints=["Use OIDC role assumption instead of long-lived keys.", "Pin by hash (--require-hashes), pin model revisions, sign artifacts with cosign."],
          deeper=f"Real audit scripts: `{REPO}/Part-4/chapter-20/exercise-03` (`audit_pipeline.py`, `generate_sbom.py`).",
          quiz=[("Best fix for hard-coded cloud keys in CI?", ["Rotate monthly", "Short-lived OIDC federation", "Base64-encode them", "Private repo"], 1, "No stored secret means nothing to steal.")])
def ex_pipeline():
    if "x203_y" not in st.session_state:
        st.session_state["x203_y"] = I.INSECURE_PIPELINE
        st.session_state["x203_r"] = I.UNPINNED_REQ
    st.text_area("Pipeline YAML (editable)", key="x203_y", height=240)
    st.text_area("requirements.txt", key="x203_r", height=100)
    c = st.columns(2)
    c[0].button("Load hardened pipeline", key="x203_sec", on_click=lambda: (_load("x203_y", I.SECURE_PIPELINE), _load("x203_r", "requests==2.31.0\n")))
    c[1].button("Reset to insecure", key="x203_ins", on_click=lambda: (_load("x203_y", I.INSECURE_PIPELINE), _load("x203_r", I.UNPINNED_REQ)))
    try:
        f = I.audit_pipeline(st.session_state["x203_y"], st.session_state["x203_r"])
    except yaml.YAMLError as e:
        st.error(f"Invalid YAML: {e}")
        return
    st.metric("Findings", len(f))
    tbl(f or [{"severity": "-", "finding": "none"}])
    st.download_button("Download SBOM of requirements", json.dumps(D.make_sbom(st.session_state["x203_r"]), indent=2), "pipeline_sbom.json", key="x203_dl")
    if not f:
        st.success("Pipeline passes the audit.")
        mark("20.3")
