import os
import json
from datetime import datetime

from reportlab.platypus import (

    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle

)

from reportlab.lib import colors
from reportlab.lib import styles
from reportlab.lib.styles import getSampleStyleSheet



def safe_load(path):

    try:

        if os.path.exists(path):

            with open(path) as f:

                return json.load(f)

    except Exception as e:

        print(

            f"[REPORT ERROR] {e}"

        )

    return None



def generate_pdf_report(

    domain,
    mode,
    risk_data,
    vuln_data,
    output_dir

):

    os.makedirs(

        output_dir,
        exist_ok=True

    )

    file_path=os.path.join(

        output_dir,

        f"{domain}_security_report.pdf"

    )

    doc=SimpleDocTemplate(

        file_path

    )

    stylesheets=getSampleStyleSheet()

    story=[]


    # ==================================
    # TITLE
    # ==================================

    story.append(

        Paragraph(

            "RiskRecon Suite Security Assessment Report",

            stylesheets["Title"]

        )

    )

    story.append(

        Spacer(1,25)

    )


    # ==================================
    # METADATA TABLE
    # ==================================

    metadata=[

        ["Target",domain],

        ["Scan Mode",mode],

        ["Generated",datetime.now().strftime(
            "%Y-%m-%d %H:%M"
        )],

        ["Risk Score",
        str(
            risk_data.get(
                "total_risk_score",
                0
            )
        )],

        ["Severity",
        risk_data.get(
            "overall_severity",
            "LOW"
        )]

    ]

    table=Table(metadata)

    table.setStyle(

        TableStyle([

            ('BACKGROUND',(0,0),(-1,0),colors.grey),

            ('BOX',(0,0),(-1,-1),1,colors.black),

            ('GRID',(0,0),(-1,-1),1,colors.black),

            ('VALIGN',(0,0),(-1,-1),"MIDDLE")

        ])

    )

    story.append(table)

    story.append(

        Spacer(1,20)

    )


    # ==================================
    # EXECUTIVE SUMMARY
    # ==================================

    story.append(

        Paragraph(

            "Executive Summary",

            stylesheets["Heading1"]

        )

    )

    summary=f"""

Target <b>{domain}</b>
was analyzed using RiskRecon Suite.

The assessment identified
<b>{len(vuln_data.get('findings',[]))}</b>
security observations.

Overall severity level:

<b>{risk_data.get(
'overall_severity'
)}</b>

"""

    story.append(

        Paragraph(

            summary,

            stylesheets["BodyText"]

        )

    )

    story.append(

        Spacer(1,20)

    )


    # ==================================
    # FINDINGS
    # ==================================

    story.append(

        Paragraph(

            "Detected Findings",

            stylesheets["Heading1"]

        )

    )

    findings=vuln_data.get(

        "findings",

        []

    )

    if findings:

        for item in findings:

            story.append(

                Paragraph(

                    f"• {item}",

                    stylesheets["Normal"]

                )

            )

    else:

        story.append(

            Paragraph(

                "No findings detected",

                stylesheets["Normal"]

            )

        )



    story.append(
        Spacer(1,20)
    )


    # ==================================
    # COMPLEX REPORT DATA
    # ==================================

    if mode=="complex":

        story.append(

            PageBreak()

        )

        story.append(

            Paragraph(

                "Advanced Reconnaissance Data",

                stylesheets["Heading1"]

            )

        )


        # SUBDOMAINS

        sub_data=safe_load(

            f"data/results/{domain}_subdomains.json"

        )

        if sub_data:

            story.append(

                Paragraph(

                    "Subdomain Analysis",

                    stylesheets["Heading2"]

                )

            )

            story.append(

                Paragraph(

                    f"Total Found: {sub_data.get('total_found',0)}",

                    stylesheets["Normal"]

                )

            )

            story.append(

                Paragraph(

                    f"Alive: {sub_data.get('alive',0)}",

                    stylesheets["Normal"]

                )

            )

            for sub in sub_data.get(

                "subdomains",

                []

            )[:20]:

                story.append(

                    Paragraph(

                        f"{sub['subdomain']} | "
                        f"{sub['status']} | "
                        f"{sub['server']}",

                        stylesheets["Normal"]

                    )

                )


        story.append(
            Spacer(1,20)
        )


        # PORTS

        port_data=safe_load(

            f"data/results/{domain}_ports.json"

        )

        if port_data:

            story.append(

                Paragraph(

                    "Open Ports",

                    stylesheets["Heading2"]

                )

            )

            for p in port_data.get(

                "ports",

                []

            ):

                story.append(

                    Paragraph(

                        f"Port: {p['port']} | "
                        f"{p['service']} | "
                        f"{p['product']} "
                        f"{p['version']}",

                        stylesheets["Normal"]

                    )

                )


        story.append(
            Spacer(1,20)
        )


        # DIRECTORIES

        dir_data=safe_load(

            f"data/results/{domain}_dirs.json"

        )

        if dir_data:

            story.append(

                Paragraph(

                    "Interesting Endpoints",

                    stylesheets["Heading2"]

                )

            )

            for d in dir_data[:20]:

                story.append(

                    Paragraph(

                        f"{d['url']} "
                        f"(Status:{d['status']})",

                        stylesheets["Normal"]

                    )

                )


    # ==================================
    # DISCLAIMER
    # ==================================

    story.append(

        Spacer(1,30)

    )

    story.append(

        Paragraph(

            "<i>Generated for educational and authorized security assessment purposes only.</i>",

            stylesheets["Italic"]

        )

    )


    doc.build(story)

    return file_path