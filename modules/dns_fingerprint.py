import socket
import json
import os
import requests
import dns.resolver


def dns_and_tech_scan(domain):

    result={

        "domain":domain,

        "ip":"Unknown",

        "dns":{

            "A":[],

            "MX":[],

            "NS":[]

        },

        "technology":{}

    }

    try:

        ip=socket.gethostbyname(domain)

        result["ip"]=ip

    except Exception as e:

        print(
            f"[DNS ERROR] IP: {e}"
        )

    # DNS records

    record_types=[

        "A",
        "MX",
        "NS"

    ]

    for rtype in record_types:

        try:

            answers=dns.resolver.resolve(

                domain,
                rtype

            )

            result["dns"][rtype]=[

                str(x)

                for x in answers

            ]

        except:

            result["dns"][rtype]=[]


    # Technology fingerprints

    try:

        response=requests.get(

            f"https://{domain}",

            timeout=5

        )

        headers=response.headers

        result["technology"]={

            "server":

            headers.get(
                "Server",
                "Unknown"
            ),

            "powered_by":

            headers.get(
                "X-Powered-By",
                "Unknown"
            )

        }

    except Exception as e:

        print(

            f"[TECH ERROR] {e}"

        )

    os.makedirs(
        "data/results",
        exist_ok=True
    )

    with open(

        f"data/results/{domain}_dns.json",

        "w"

    ) as f:

        json.dump(
            result,
            f,
            indent=4
        )

    return result