import subprocess
import json
import os
import socket
import requests
from concurrent.futures import ThreadPoolExecutor


def analyze_subdomain(sub):

    result={

        "subdomain":sub,

        "alive":False,

        "ip":"Unknown",

        "status":"Unknown",

        "server":"Unknown"

    }

    try:

        ip=socket.gethostbyname(sub)

        result["ip"]=ip

    except:
        return result

    schemes=[

        f"https://{sub}",

        f"http://{sub}"

    ]

    for url in schemes:

        try:

            r=requests.get(

                url,

                timeout=3,

                allow_redirects=True,

                headers={

                    "User-Agent":

                    "RiskRecon/2.5"

                }

            )

            result["alive"]=True

            result["status"]=r.status_code

            result["server"]=r.headers.get(

                "Server",

                "Unknown"

            )

            break

        except:
            pass

    return result


def enumerate_subdomains(domain):

    final_results=[]

    try:

        process=subprocess.run(

            [

                "subfinder",

                "-d",

                domain,

                "-silent"

            ],

            capture_output=True,

            text=True,

            timeout=60

        )

        subdomains=list(

            set(

                process.stdout.splitlines()

            )

        )

    except Exception as e:

        print(

            f"[SUBFINDER ERROR] {e}"

        )

        subdomains=[]


    print(

        f"[+] Found {len(subdomains)} subdomains"

    )

    try:

        with ThreadPoolExecutor(
            max_workers=20
        ) as executor:

            final_results=list(

                executor.map(

                    analyze_subdomain,

                    subdomains

                )

            )

    except Exception as e:

        print(

            f"[THREAD ERROR] {e}"

        )


    alive_count=len([

        x

        for x in final_results

        if x["alive"]

    ])


    output={

        "domain":domain,

        "total_found":

        len(subdomains),

        "alive":

        alive_count,

        "subdomains":

        final_results

    }

    os.makedirs(

        "data/results",

        exist_ok=True

    )

    with open(

        f"data/results/{domain}_subdomains.json",

        "w"

    ) as f:

        json.dump(

            output,

            f,

            indent=4

        )

    return output