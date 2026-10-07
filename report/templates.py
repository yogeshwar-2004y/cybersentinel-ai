"""Report sections shared by Markdown and PDF renderers."""

TEXT_SECTIONS = (
    ("Incident Summary", "incident_summary"),
    ("Threat Explanation", "threat_explanation"),
    ("Technical Explanation", "technical_explanation"),
    ("Business Impact", "business_impact"),
)
LIST_SECTIONS = (
    ("Attack Chain (Observed and Hypothesized)", "attack_chain"),
    ("Recommended Actions", "recommended_actions"),
    ("Recommended Mitigation", "recommended_mitigation"),
    ("SOC Checklist", "soc_checklist"),
    ("Next Investigation Steps", "next_investigation_steps"),
    ("Recovery", "recovery"),
    ("Uncertainties", "uncertainties"),
)
