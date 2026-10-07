"""Safe Markdown, JSON, and paginated PDF bytes from the same incident contract."""

from io import BytesIO
from html import escape
import json
import re
import unicodedata
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from report.templates import TEXT_SECTIONS, LIST_SECTIONS
from config import ROOT


class ReportGenerator:
    @staticmethod
    def json_bytes(report: dict) -> bytes:
        return json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8")

    @staticmethod
    def markdown(report: dict) -> str:
        def safe(value: object) -> str:
            value = str(value).replace("\n", " ").replace("\r", "")
            value = re.sub(r"([\\`*_{}\[\]()#+!|])", r"\\\1", value)
            return escape(value, quote=False)

        lines = [
            "# CyberSentinel AI Incident Report",
            "",
            f"**Incident ID:** {report['incident_id']}",
            f"**Event ID:** {report['event_id']}",
            f"**Threat Name:** {safe(report['threat_name'])}",
            f"**Timestamp:** {safe(report['timestamp'])}",
            f"**Generated:** {safe(report['generated_at'])}",
            f"**Status:** {safe(report['status'])}",
            f"**Severity:** {report['severity']}",
            f"**Analysis Confidence:** {report['confidence']:.0%} (heuristic)",
            f"**Risk Score:** {report['risk_score']}/100 (heuristic)",
            "",
            "> Analyst decision support. Actions require accountable human review.",
            "",
        ]
        for title, key in TEXT_SECTIONS:
            lines += [f"## {title}", "", safe(report[key]), ""]
        lines += ["## MITRE ATT&CK", ""]
        for item in report["mitre_mapping"]:
            lines += [f"- {item['id']} - {safe(item['name'])}: {safe(item['rationale'])} [{safe(item['source_id'])}]"]
        if not report["mitre_mapping"]:
            lines += ["No supported technique mapping asserted."]
        lines += ["", "## Evidence", "", "| Field | Value |", "|---|---|"]
        lines += [f"| {safe(k)} | {safe(v)} |" for k, v in report["evidence"].items()]
        for title, key in LIST_SECTIONS:
            lines += ["", f"## {title}", ""] + [f"- {safe(item)}" for item in report[key]]
        lines += ["", "## Response Playbook", ""]
        for step in report["playbook"]:
            lines += [
                f"### {safe(step['phase'])}",
                "",
                f"- Action: {safe(step['action'])}",
                f"- Owner: {safe(step['owner'])}",
                f"- Approval required: {step['approval_required']}",
                f"- Validation: {safe(step['validation'])}",
                "",
            ]
        lines += ["## Sources", ""]
        for doc in report["sources"]:
            lines += [f"- {safe(doc['source_id'])} - {safe(doc['title'])} (similarity {doc['score']:.4f})"]
        lines += ["", "## Provenance", ""] + [f"- {safe(k)}: {safe(v)}" for k, v in report["provenance"].items()]
        lines += ["", "## Agent Execution Trace", ""] + [
            f"- {safe(t['agent'])}: {t['duration_ms']} ms ({t['status']})" for t in report["agent_trace"]
        ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def pdf_bytes(report: dict) -> bytes:
        """Wrap all user/provider text after HTML escaping; never interpret evidence markup."""
        buffer = BytesIO()
        font_path = ROOT / "assets" / "fonts" / "DejaVuSans.ttf"
        font = "Helvetica"
        if font_path.exists():
            font = "CyberSentinelSans"
            if font not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(font, str(font_path)))
        styles = getSampleStyleSheet()
        for key in ["BodyText", "Normal", "Heading1", "Heading2", "Heading3", "Title"]:
            styles[key].fontName = font
        styles["BodyText"].fontSize = 9
        styles["BodyText"].leading = 12
        styles["BodyText"].wordWrap = "CJK"
        styles["Heading2"].textColor = colors.HexColor("#087f8c")
        styles["Heading2"].fontSize = 13
        styles["Heading2"].spaceBefore = 15
        styles.add(ParagraphStyle(name="SmallCell", fontName=font, fontSize=8, leading=11, wordWrap="CJK"))

        # Explicit ASCII rendering prevents missing glyphs in arbitrary event text.
        def plain(value: object) -> str:
            return unicodedata.normalize("NFKD", str(value)).encode("ascii", "replace").decode("ascii")

        def para(value: object, style: str = "BodyText") -> Paragraph:
            return Paragraph(escape(plain(value)).replace("\n", "<br/>"), styles[style])

        story = [para("CyberSentinel AI", "Title"), para("SOC INCIDENT REPORT", "Heading2"), Spacer(1, 12)]
        metadata = [
            ("Incident ID", report["incident_id"]),
            ("Threat", report["threat_name"]),
            ("Event time (UTC)", report["timestamp"]),
            ("Generated at", report["generated_at"]),
            ("Severity / Status", f"{report['severity']} / {report['status']}"),
            ("Confidence / Risk", f"{report['confidence']:.0%} heuristic / {report['risk_score']}/100 heuristic"),
        ]
        table = Table([[para(a, "SmallCell"), para(b, "SmallCell")] for a, b in metadata], colWidths=[115, 380])
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e7f5f5")),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cedade")),
                    ("PADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        story += [
            table,
            Spacer(1, 12),
            para(
                "Decision support only. Confidence and risk are heuristic. "
                "Disruptive response actions require human approval. Unsupported Unicode is replaced with ? in this PDF; JSON preserves original text."
            ),
        ]
        for title, key in TEXT_SECTIONS:
            story += [para(title, "Heading2"), para(report[key])]
        story += [para("MITRE ATT&CK (Candidate Mappings)", "Heading2")]
        for item in report["mitre_mapping"]:
            story.append(para(f"{item['id']} - {item['name']}: {item['rationale']} [{item['source_id']}]"))
        if not report["mitre_mapping"]:
            story.append(para("No supported technique mapping asserted."))
        story.append(para("Evidence", "Heading2"))
        for key, value in report["evidence"].items():
            story.append(para(f"{key}: {value}"))
        for title, key in LIST_SECTIONS:
            story.append(para(title, "Heading2"))
            for index, item in enumerate(report[key], 1):
                story.append(para(f"{index}. {item}"))
        story.append(para("Response Playbook", "Heading2"))
        for step in report["playbook"]:
            story += [
                para(step["phase"], "Heading3"),
                para(step["action"]),
                para(f"Owner: {step['owner']} | Approval required: {step['approval_required']}"),
                para("Validation: " + step["validation"]),
            ]
        story.append(para("Retrieved Sources", "Heading2"))
        for doc in report["sources"]:
            story.append(para(f"{doc['source_id']} - {doc['title']} | similarity={doc['score']:.4f}"))
            references = (
                doc["text"].split("## References")[-1].split("## Source note")[0]
                if "## References" in doc["text"]
                else ""
            )
            if references:
                story.append(para(references))
        story.append(para("Provenance", "Heading2"))
        for key, value in report["provenance"].items():
            story.append(para(f"{key}: {value}"))
        trace_section = [para("Agent Execution Trace", "Heading2")]
        trace_section.extend(
            para(f"{trace['agent']}: {trace['duration_ms']} ms ({trace['status']})") for trace in report["agent_trace"]
        )
        story.append(KeepTogether(trace_section))

        def footer(canvas, doc):
            canvas.saveState()
            canvas.setFont(font, 8)
            canvas.setFillColor(colors.HexColor("#526477"))
            canvas.drawString(42, 26, "CyberSentinel AI | Confidential incident evidence")
            canvas.drawRightString(A4[0] - 42, 26, f"Page {doc.page}")
            canvas.restoreState()

        SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=42,
            leftMargin=42,
            topMargin=40,
            bottomMargin=44,
            title=report["incident_id"],
            author="CyberSentinel AI",
        ).build(story, onFirstPage=footer, onLaterPages=footer)
        return buffer.getvalue()
