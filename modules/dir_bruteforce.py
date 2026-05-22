import requests
import json
import os


def dir_bruteforce(domain):

    words=[

        "admin",
        "login",
        "dashboard",
        "api",
        "backup",
        "test",
        "robots.txt",
        ".git",
        "dev",
        "uploads",
        "config",
        "panel"

    ]

    findings=[]

    os.makedirs(
        "data/results",
        exist_ok=True
    )

    headers={

        "User-Agent":

        "RiskRecon/2.5"

    }

    for word in words:

        url=f"https://{domain}/{word}"

        try:

            r=requests.get(

                url,

                headers=headers,

                timeout=3,

                allow_redirects=False

            )

            if r.status_code in [

                200,
                301,
                302,
                401,
                403

            ]:

                findings.append({

                    "path":word,

                    "url":url,

                    "status":

                    r.status_code,

                    "size":

                    len(r.text)

                })

        except Exception as e:

            print(

                f"[DIR ERROR] {word}: {e}"

            )

    with open(

        f"data/results/{domain}_dirs.json",

        "w"

    ) as f:

        json.dump(

            findings,

            f,

            indent=4

        )

    return findings