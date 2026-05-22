def evaluate_compliance(vuln_data):

    compliance=[]

    findings=vuln_data.get(
        "findings",
        []
    )

    owasp_mapping={

        "X-Frame-Options":{

            "standard":"OWASP",

            "title":"A05 Security Misconfiguration"

        },

        "CSP":{

            "standard":"OWASP",

            "title":"A05 Security Misconfiguration"

        },

        "Directory Listing":{

            "standard":"OWASP",

            "title":"A01 Broken Access Control"

        },

        "Outdated":{

            "standard":"OWASP",

            "title":"A06 Vulnerable Components"

        },

        "SQL":{

            "standard":"OWASP",

            "title":"A03 Injection"

        }

    }

    for item in findings:

        matched=False

        for keyword,data in owasp_mapping.items():

            if keyword.lower() in item.lower():

                compliance.append({

                    "standard":data["standard"],

                    "title":data["title"],

                    "status":"Violation",

                    "reason":item

                })

                matched=True

                break

        if not matched:

            compliance.append({

                "standard":"OWASP",

                "title":"General Security Observation",

                "status":"Review",

                "reason":item

            })

    return compliance