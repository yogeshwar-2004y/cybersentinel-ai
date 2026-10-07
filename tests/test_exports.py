"""Export validity and malicious-markup resilience."""

import json
from io import BytesIO
from report.generator import ReportGenerator
from pypdf import PdfReader


def test_json_roundtrip(report):
    value = json.loads(ReportGenerator.json_bytes(report))
    assert value["incident_id"] == report["incident_id"] and len(value["agent_trace"]) == 5


def test_markdown_sections(report):
    text = ReportGenerator.markdown(report)
    for title in ["Evidence", "Response Playbook", "MITRE ATT&CK", "Recovery", "Provenance"]:
        assert "## " + title in text


def test_pdf_complete_and_parseable(report):
    pdf = ReportGenerator.pdf_bytes(report)
    assert pdf.startswith(b"%PDF")
    reader = PdfReader(BytesIO(pdf))
    text = "".join(page.extract_text() for page in reader.pages)
    assert report["incident_id"] in text and "Response Playbook" in text and "Agent Execution Trace" in text
    assert len(reader.pages) >= 2


def test_untrusted_markup_export(report):
    report["evidence"]["message"] = '<script>alert(1)</script> & <img src="file:///secret">'
    report["incident_summary"] = "<b>untrusted</b>"
    markdown = ReportGenerator.markdown(report)
    assert "<script>" not in markdown and "&lt;script&gt;" in markdown
    pdf = ReportGenerator.pdf_bytes(report)
    assert b"%PDF" in pdf
