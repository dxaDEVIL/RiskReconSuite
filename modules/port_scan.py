import nmap
import json
import os


def port_scan(

    domain,

    full_scan=False

):

    results={

        "domain":domain,

        "hosts":[],

        "ports":[],

        "error":None

    }

    try:

        scanner=nmap.PortScanner()

        # SIMPLE VS COMPLEX

        scan_args=(
            "-p- -sV -sC"
            if full_scan
            else "-F -sV"
        )

        scanner.scan(

            domain,

            arguments=scan_args

        )

        for host in scanner.all_hosts():

            results["hosts"].append({

                "host":host,

                "state":

                scanner[host].state()

            })

            tcp_data=scanner[
                host
            ].get(
                "tcp",
                {}
            )

            for port,data in tcp_data.items():

                if data.get(
                    "state"
                )=="open":

                    results["ports"].append({

                        "port":port,

                        "service":

                        data.get(
                            "name",
                            "unknown"
                        ),

                        "product":

                        data.get(
                            "product",
                            ""
                        ),

                        "version":

                        data.get(
                            "version",
                            ""
                        ),

                        "reason":

                        data.get(
                            "reason",
                            ""
                        )

                    })

    except Exception as e:

        results["error"]=str(e)

        print(

            f"[PORT ERROR] {e}"

        )

    os.makedirs(
        "data/results",
        exist_ok=True
    )

    with open(

        f"data/results/{domain}_ports.json",

        "w"

    ) as f:

        json.dump(

            results,

            f,

            indent=4

        )

    return results