def generate_recommendations(
    vuln_data
):

    recommendations=[]

    findings=vuln_data.get(
        "findings",
        []
    )

    recommendation_map={

        "X-Frame":{

            "severity":"MEDIUM",

            "recommendation":

            "Enable X-Frame-Options headers to mitigate clickjacking attacks."

        },

        "CSP":{

            "severity":"HIGH",

            "recommendation":

            "Configure a strict Content Security Policy to reduce XSS exposure."

        },

        "Directory":{

            "severity":"HIGH",

            "recommendation":

            "Disable directory listing and restrict sensitive paths."

        },

        "Outdated":{

            "severity":"HIGH",

            "recommendation":

            "Update server software and components to supported versions."

        },

        "SQL":{

            "severity":"CRITICAL",

            "recommendation":

            "Use parameterized queries and input validation."

        },

        "Admin":{

            "severity":"MEDIUM",

            "recommendation":

            "Restrict administrative endpoints and enable authentication."

        }

    }

    for item in findings:

        matched=False

        for keyword,data in recommendation_map.items():

            if keyword.lower() in item.lower():

                recommendations.append({

                    "issue":item,

                    "severity":data[
                        "severity"
                    ],

                    "recommendation":
                    data[
                        "recommendation"
                    ]

                })

                matched=True

                break

        if not matched:

            recommendations.append({

                "issue":item,

                "severity":"LOW",

                "recommendation":

                "Manual investigation recommended."

            })

    return recommendations