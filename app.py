"""Enterprise AI Security for Architects - hands-on labs.  Run: streamlit run app.py"""
import json

import streamlit as st

import ex_part1, ex_part2, ex_part3, ex_part4  # noqa: F401,E401  (registers the exercises)
import range_core as R
from labs import LABS

st.set_page_config(page_title="AI Security Labs", page_icon="🛡️", layout="wide")
SECTIONS = ["Course labs (0-14)", "Field exercises: Part 1 Foundations", "Field exercises: Part 2 Attacks",
            "Field exercises: Part 3 Defenses", "Field exercises: Part 4 Cloud & MLOps", "Progress & report"]

st.sidebar.title("🛡️ AI Security Labs")
section = st.sidebar.radio("Section", SECTIONS, key="section")
st.sidebar.divider()


def progress_page() -> None:
    st.title("Progress & report")
    s = R.summary()
    c = st.columns(4)
    c[0].metric("Field labs done", f"{s['labs_done']}/{s['labs_total']}")
    c[1].metric("Knowledge-check score", f"{s['quiz_correct']}/{s['quiz_total']}" if s["quiz_total"] else "-")
    c[2].metric("Course labs touched", f"{len(st.session_state.get('done', set()))}/{len(LABS)}")
    risk = st.session_state.get("rt_risk")
    c[3].metric("Last red-team risk", f"{risk['score']} ({risk['rating']})" if risk else "-")
    R.tbl([{"exercise": e.label, "part": e.part, "lab": "done" if R.state(e.id)["lab"] else "-",
            "quiz": f"{R.state(e.id)['quiz'][0]}/{R.state(e.id)['quiz'][1]}" if R.state(e.id)["quiz"][1] else "-"} for e in R.REG.values()])
    report = {"summary": s, "course_labs_touched": sorted(st.session_state.get("done", set())), "red_team_risk": risk,
              "exercises": {k: R.state(k) for k in R.REG}}
    st.download_button("Download progress (JSON)", json.dumps(report, indent=2, default=list), "progress.json", key="prog_dl")


if section.startswith("Course"):
    choice = st.sidebar.radio("Select a lab", list(LABS), key="nav")
    st.sidebar.progress(len(st.session_state.get("done", set())) / len(LABS), text="Course-lab progress")
    LABS[choice]()
elif section.startswith("Progress"):
    progress_page()
else:
    part = int(section.split("Part ")[1][0])
    exs = R.exercises_for(part)
    sel = st.sidebar.radio("Exercise", [e.id for e in exs], key=f"ex_{part}", format_func=lambda i: R.REG[i].label)
    R.render(R.REG[sel])
st.sidebar.caption("Deterministic simulations: no API keys, no network. Scenario & exercise structure adapted from PacktPublishing/AI-Under-Attack (MIT).")
