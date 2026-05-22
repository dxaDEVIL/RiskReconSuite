import requests
import json
import os
import time


def vuln_scan(domain):

    findings=[]

    metadata={

        "target":domain,
        "status":"Unknown",
        "server":"Unknown",
        "response_time":"Unknown"

    }

    headers_to_check=[

        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"

    ]

    session=requests.Session()

    try:

        start=time.time()

        response=session.get(

            f"https://{domain}",

            timeout=8,

            allow_redirects=True,

            headers={

                "User-Agent":

                "RiskRecon/3.0"

            }

        )

        elapsed=round(
            time.time()-start,
            2
        )

        metadata["response_time"]=f"{elapsed}s"

        metadata["status"]=response.status_code

        metadata["server"]=response.headers.get(

            "Server",

            "Unknown"

        )

        headers=response.headers


        # =====================
        # SECURITY HEADERS
        # =====================

        for h in headers_to_check:

            if h not in headers:

                findings.append(

                    f"Missing {h}"

                )


        # =====================
        # SERVER DISCLOSURE
        # =====================

        server=headers.get(
            "Server",
            ""
        )

        if server:

            findings.append(

                f"Server identified: {server}"

            )

            weak_versions=[

                "apache/2.2",
                "apache/2.0",
                "iis/6"

            ]

            if any(

                x in server.lower()

                for x in weak_versions

            ):

                findings.append(

                    f"Outdated Server: {server}"

                )


        # =====================
        # TECHNOLOGY DISCLOSURE
        # =====================

        if headers.get(

            "X-Powered-By"

        ):

            findings.append(

                "Technology disclosure via X-Powered-By"

            )


        # =====================
        # REDIRECTS
        # =====================

        if len(
            response.history
        )>2:

            findings.append(

                "Multiple redirects detected"

            )


        # =====================
        # HTTP METHODS
        # =====================

        try:

            options=session.options(

                f"https://{domain}",

                timeout=5

            )

            methods=options.headers.get(

                "Allow",

                ""

            )

            dangerous=[

                "PUT",
                "DELETE",
                "TRACE"

            ]

            for method in dangerous:

                if method in methods:

                    findings.append(

                        f"Dangerous HTTP method enabled: {method}"

                    )

        except:
            pass


        # =====================
        # COOKIE FLAGS
        # =====================

        cookies=response.cookies

        for cookie in cookies:

            if not cookie.secure:

                findings.append(

                    f"Insecure Cookie: {cookie.name}"

                )


        # =====================
        # ROBOTS CHECK
        # =====================

        try:

            robots=session.get(

                f"https://{domain}/robots.txt",

                timeout=3

            )

            if robots.status_code==200:

                findings.append(

                    "robots.txt exposed"

                )

        except:
            pass


        # =====================
        # COMMON EXPOSURES
        # =====================

        paths=[

            ".git",

            "backup.zip",

            "config.php",

            ".env",

            "admin"

        ]

        for p in paths:

            try:

                r=session.get(

                    f"https://{domain}/{p}",

                    timeout=2

                )

                if r.status_code in [

                    200,
                    401,
                    403

                ]:

                    findings.append(

                        f"Potential exposure: {p}"

                    )

            except:
                pass


    except Exception as e:

        findings.append(
            "Target unreachable"
        )

        print(
            f"[VULN ERROR] {e}"
        )


    result={

        "metadata":metadata,

        "total_findings":

        len(findings),

        "findings":findings

    }

    os.makedirs(

        "data/results",

        exist_ok=True

    )

    with open(

        f"data/results/{domain}_vulnerabilities.json",

        "w"

    ) as f:

        json.dump(

            result,

            f,

            indent=4

        )

    return result