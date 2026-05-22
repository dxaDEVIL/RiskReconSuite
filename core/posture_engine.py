def calculate_security_posture(

    vuln_data,
    risk_data,
    compliance

):

    score = 100

    findings = vuln_data.get(
        "findings",
        []
    )

    severity = risk_data.get(
        "overall_severity",
        "LOW"
    )

    # Base deduction

    score -= len(findings) * 5

    # Severity impact

    severity_penalty = {

        "LOW":5,
        "MEDIUM":15,
        "HIGH":25

    }

    score -= severity_penalty.get(
        severity,
        0
    )

    # Compliance impact

    violations = len(

        [

            item
            for item in compliance

            if item["status"]=="Violation"

        ]

    )

    score -= violations * 3

    # Clamp score

    score=max(
        0,
        min(score,100)
    )

    # Grade system

    if score>=90:

        grade="A"

        status="Excellent"

    elif score>=75:

        grade="B"

        status="Strong"

    elif score>=60:

        grade="C"

        status="Moderate"

    elif score>=40:

        grade="D"

        status="Weak"

    else:

        grade="F"

        status="Critical"

    return{

        "score":score,

        "grade":grade,

        "status":status

    }