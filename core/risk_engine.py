import json
import os


def generate_risk_report(domain):

    file = f"data/results/{domain}_vulnerabilities.json"

    default_report={

        "total_risk_score":0,

        "overall_severity":"LOW",

        "findings":[]

    }

    if not os.path.exists(file):

        return default_report

    try:

        with open(file) as f:

            vuln_data=json.load(f)

    except:

        return default_report


    findings=vuln_data.get(
        "findings",
        []
    )

    risk_weights={

        "CSP":15,

        "X-Frame":10,

        "Directory":20,

        "Outdated":25,

        "SQL":40,

        "Admin":15,

        "unreachable":5

    }

    score=0

    for finding in findings:

        matched=False

        for keyword,weight in risk_weights.items():

            if keyword.lower() in finding.lower():

                score+=weight

                matched=True

                break

        if not matched:

            score+=5

    score=min(score,100)

    if score>=70:

        severity="HIGH"

    elif score>=30:

        severity="MEDIUM"

    else:

        severity="LOW"

    report={

        "total_risk_score":score,

        "overall_severity":severity,

        "findings":findings

    }

    with open(

        f"data/results/{domain}_risk_report.json",

        "w"

    ) as f:

        json.dump(
            report,
            f,
            indent=4
        )

    return report