def generate_risk_explanation(
    vuln_data,
    risk_data
):

    explanations=[]

    findings=vuln_data.get(
        "findings",
        []
    )

    explanation_map={

        "X-Frame-Options":

        "Missing X-Frame-Options may expose the application to clickjacking attacks.",


        "CSP":

        "Missing Content Security Policy can increase XSS attack exposure.",


        "Directory":

        "Exposed directories may reveal sensitive resources or internal structures.",


        "Outdated":

        "Outdated technologies can contain publicly known vulnerabilities.",


        "SQL":

        "Potential SQL related behavior may indicate injection risk.",


        "unreachable":

        "Target accessibility issue detected."
    }

    for item in findings:

        matched=False

        for keyword,message in explanation_map.items():

            if keyword.lower() in item.lower():

                explanations.append(
                    message
                )

                matched=True

                break

        if not matched:

            explanations.append(

                f"Security observation detected: {item}"

            )

    severity=risk_data.get(
        "overall_severity",
        "LOW"
    )

    explanations.append(

        f"Overall calculated risk severity: {severity}"

    )

    return explanations