
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


NAVY = colors.HexColor("#163A5F")
BLUE = colors.HexColor("#245C91")
LIGHT_BLUE = colors.HexColor("#EAF2F8")
LIGHT_GREY = colors.HexColor("#F4F6F8")
DARK_GREY = colors.HexColor("#444444")
BORDER_GREY = colors.HexColor("#D5DCE3")


def _safe(value):
    """Escape text before placing it into a ReportLab paragraph."""
    return escape(str(value))


def _add_label_value(story, styles, label, value):
    """Add a readable label and value as separate report text."""
    story.append(
        Paragraph(
            f"<b>{_safe(label)}:</b> {_safe(value)}",
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 5))


def _add_section(story, styles, title):
    story.append(Spacer(1, 8))
    story.append(Paragraph(_safe(title), styles["SectionHeading"]))
    story.append(Spacer(1, 6))


def _add_bullet(story, styles, text):
    story.append(
        Paragraph(
            f"&bull;&nbsp;&nbsp;{_safe(text)}",
            styles["ReportBody"],
        )
    )
    story.append(Spacer(1, 4))


def generate_pdf_report(
    url_result=None,
    message_result=None,
    explanation="",
) -> bytes:
    """Generate a professionally formatted PDF investigation report."""

    url_result = url_result or {}
    message_result = message_result or {}

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="PhishGuard AI Investigation Report",
        author="PhishGuard AI",
        subject="Preliminary URL and message security analysis",
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="BrandTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            alignment=TA_CENTER,
            textColor=NAVY,
            spaceAfter=5,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=12,
            leading=16,
            alignment=TA_CENTER,
            textColor=BLUE,
            spaceAfter=12,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=NAVY,
            spaceBefore=5,
            spaceAfter=5,
            keepWithNext=True,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=DARK_GREY,
            splitLongWords=True,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallNote",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=DARK_GREY,
        )
    )

    story = []

    # Report heading
    story.append(Paragraph("PhishGuard AI", styles["BrandTitle"]))
    story.append(
        Paragraph(
            "PHISHING INVESTIGATION REPORT",
            styles["ReportSubtitle"],
        )
    )

    intro = Table(
        [[
            Paragraph(
                "<b>Purpose</b><br/>"
                "Preliminary analysis of URL characteristics and "
                "message warning indicators. This report is not a "
                "certification that content is safe or malicious.",
                styles["ReportBody"],
            )
        ]],
        colWidths=[174 * mm],
    )

    intro.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER_GREY),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )

    story.extend([intro, Spacer(1, 12)])

    # URL analysis
    _add_section(story, styles, "1. URL Analysis")

    url = url_result.get("url", "Not provided")
    status = url_result.get("status", "Not analyzed")
    prediction = url_result.get("prediction", "Not available")
    score = url_result.get("phishing_score")

    url_rows = [
        [
            Paragraph("<b>Field</b>", styles["ReportBody"]),
            Paragraph("<b>Result</b>", styles["ReportBody"]),
        ],
        [
            Paragraph("URL under investigation", styles["ReportBody"]),
            Paragraph(_safe(url), styles["ReportBody"]),
        ],
        [
            Paragraph("Analysis status", styles["ReportBody"]),
            Paragraph(_safe(status), styles["ReportBody"]),
        ],
        [
            Paragraph("Model prediction", styles["ReportBody"]),
            Paragraph(_safe(prediction), styles["ReportBody"]),
        ],
        [
            Paragraph(
                "Estimated phishing probability",
                styles["ReportBody"],
            ),
            Paragraph(
                _safe(f"{score:.1%}")
                if isinstance(score, (int, float))
                else "Unavailable",
                styles["ReportBody"],
            ),
        ],
    ]

    url_table = Table(
        url_rows,
        colWidths=[61 * mm, 113 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )

    url_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BLUE),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                LIGHT_GREY,
            ]),
        ])
    )

    story.extend([url_table, Spacer(1, 8)])

    if url_result.get("status") == "success" and isinstance(
        score, (int, float)
    ):
        story.append(
            Paragraph(
                "<b>Interpretation:</b> This percentage is the model's "
                "estimated phishing probability, not a verified measure "
                "of the website's safety.",
                styles["SmallNote"],
            )
        )

    features = url_result.get("features", {})

    if features:
        _add_section(story, styles, "Extracted URL Features")

        feature_rows = [
            [
                Paragraph("<b>Feature</b>", styles["ReportBody"]),
                Paragraph("<b>Value</b>", styles["ReportBody"]),
            ]
        ]

        for name, value in features.items():
            feature_rows.append([
                Paragraph(_safe(name), styles["ReportBody"]),
                Paragraph(_safe(value), styles["ReportBody"]),
            ])

        feature_table = Table(
            feature_rows,
            colWidths=[110 * mm, 64 * mm],
            repeatRows=1,
            hAlign="LEFT",
        )

        feature_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BLUE),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER_GREY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.white,
                    LIGHT_GREY,
                ]),
            ])
        )

        story.extend([feature_table, Spacer(1, 8)])

    # Message analysis, kept separate from the independently entered URL
    _add_section(story, styles, "2. Message Analysis")

    if message_result:
        _add_label_value(
            story,
            styles,
            "Summary",
            message_result.get(
                "summary",
                "Message analysis completed.",
            ),
        )

        message_urls = message_result.get("urls", [])

        if message_urls:
            story.append(
                Paragraph(
                    "<b>URLs extracted from the message:</b>",
                    styles["ReportBody"],
                )
            )
            story.append(Spacer(1, 4))

            for message_url in message_urls:
                _add_bullet(story, styles, message_url)
        else:
            _add_label_value(
                story,
                styles,
                "URLs extracted from the message",
                "None detected",
            )

        indicators = message_result.get("indicators", [])

        if indicators:
            story.append(
                Paragraph(
                    "<b>Potential warning indicators</b>",
                    styles["ReportBody"],
                )
            )
            story.append(Spacer(1, 4))

            for indicator in indicators:
                indicator_type = indicator.get("type", "Indicator")
                evidence = indicator.get("evidence", [])
                evidence_text = ", ".join(
                    str(item) for item in evidence
                )

                _add_bullet(
                    story,
                    styles,
                    f"{indicator_type}: {evidence_text or 'No details supplied'}",
                )
        else:
            story.append(
                Paragraph(
                    "No configured warning indicators were detected. "
                    "This does not prove the message is safe.",
                    styles["ReportBody"],
                )
            )
    else:
        story.append(
            Paragraph(
                "No message was submitted for analysis.",
                styles["ReportBody"],
            )
        )

    # Explanation: each line becomes a separate paragraph or bullet.
    _add_section(story, styles, "3. Investigation Explanation")

    if explanation and str(explanation).strip():
        for line in str(explanation).splitlines():
            cleaned = line.strip()

            if not cleaned:
                continue

            # Remove a leading Markdown bullet so formatting stays clean.
            if cleaned.startswith("- "):
                cleaned = cleaned[2:].strip()
                _add_bullet(story, styles, cleaned)
            else:
                story.append(
                    Paragraph(_safe(cleaned), styles["ReportBody"])
                )
                story.append(Spacer(1, 5))
    else:
        story.append(
            Paragraph(
                "No additional explanation was supplied.",
                styles["ReportBody"],
            )
        )

    # Safety guidance
    _add_section(story, styles, "4. Safety Recommendations")

    safety_items = [
        "Do not enter passwords, OTPs, or payment information through links in unsolicited messages.",
        "Verify requests using the organization's official website or a known contact channel.",
        "Do not assume a URL is safe simply because it uses HTTPS or received a low model score.",
        "Treat model predictions and message indicators as preliminary evidence, not definitive proof.",
    ]

    safety_content = [
        Paragraph(
            "<b>Important safety guidance</b>",
            styles["ReportBody"],
        ),
        Spacer(1, 5),
    ]

    for item in safety_items:
        safety_content.append(
            Paragraph(
                f"&bull;&nbsp;&nbsp;{_safe(item)}",
                styles["ReportBody"],
            )
        )
        safety_content.append(Spacer(1, 4))

    safety_box = Table(
        [[safety_content]],
        colWidths=[174 * mm],
    )

    safety_box.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER_GREY),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )

    story.extend([safety_box, Spacer(1, 12)])

    story.append(
        Paragraph(
            "PhishGuard AI | Cybersecurity awareness and preliminary "
            "investigation tool",
            styles["SmallNote"],
        )
    )

    document.build(story)

    return buffer.getvalue()
