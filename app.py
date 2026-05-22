from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_from_directory
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import secrets
import json
import os
import uuid
import re


# ==========================
# ENV
# ==========================

load_dotenv()


# ==========================
# MODULES
# ==========================

from modules.dns_fingerprint import dns_and_tech_scan
from modules.vuln_scan import vuln_scan
from modules.subdomain_enum import enumerate_subdomains
from modules.port_scan import port_scan
from modules.dir_bruteforce import dir_bruteforce


# ==========================
# CORE
# ==========================

from core.risk_engine import generate_risk_report
from core.intelligence_engine import generate_risk_explanation
from core.compliance_engine import evaluate_compliance
from core.recommendation_engine import generate_recommendations
from core.posture_engine import calculate_security_posture


# ==========================
# REPORTS
# ==========================

from reports.report_generator import generate_pdf_report


app=Flask(__name__)


# ==========================
# SECRET
# ==========================

app.secret_key=os.environ.get(

    "SECRET_KEY",

    secrets.token_hex(32)

)


USERS_FILE="data/users/users.json"


# ==========================
# HELPERS
# ==========================

def load_json(path,default=None):

    if default is None:

        default={}

    try:

        if os.path.exists(path):

            with open(

                path,

                encoding="utf-8"

            ) as f:

                return json.load(f)

    except Exception as e:

        print(

            f"[JSON ERROR] {e}"

        )

    return default


def save_json(path,data):

    os.makedirs(

        os.path.dirname(path),

        exist_ok=True

    )

    with open(

        path,

        "w",

        encoding="utf-8"

    ) as f:

        json.dump(

            data,

            f,

            indent=4

        )


def load_users():

    return load_json(

        USERS_FILE,

        []

    )


def save_users(users):

    save_json(

        USERS_FILE,

        users

    )


def normalize_domain(domain):

    domain=domain.strip().lower()

    domain=domain.replace(

        "https://",

        ""

    )

    domain=domain.replace(

        "http://",

        ""

    )

    domain=domain.replace(

        "/",

        ""

    )

    return domain


def validate_domain(domain):

    pattern=r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'

    return re.match(

        pattern,

        domain

    )


# ==========================
# AUTH GUARD
# ==========================

@app.before_request
def auth_guard():

    public=[

        "login",
        "signup",
        "static"

    ]

    if (

        request.endpoint

        not in public

        and

        "user_id"

        not in session

    ):

        return redirect(

            url_for(

                "login"

            )

        )


# ==========================
# SIGNUP
# ==========================

@app.route(

"/signup",

methods=[

"GET",

"POST"

]

)

def signup():

    if request.method=="POST":

        username=request.form.get(

            "username"

        ).strip()

        password=request.form.get(

            "password"

        )

        users=load_users()


        for user in users:

            if (

                user[
                    "username"
                ].lower()

                ==

                username.lower()

            ):

                return (

                    "Username already exists"

                )


        user_id=str(

            uuid.uuid4()

        )


        users.append({

            "user_id":

            user_id,

            "username":

            username,

            "password_hash":

            generate_password_hash(

                password

            )

        })


        save_users(

            users

        )


        user_dir=(

            f"data/users/{user_id}"

        )


        os.makedirs(

            f"{user_dir}/reports",

            exist_ok=True

        )


        save_json(

            f"{user_dir}/scan_history.json",

            []

        )


        return redirect(

            url_for(

                "login"

            )

        )


    return render_template(

        "signup.html"

    )


# ==========================
# LOGIN
# ==========================

@app.route(

"/login",

methods=[

"GET",

"POST"

]

)

def login():

    if request.method=="POST":

        username=request.form.get(

            "username"

        )

        password=request.form.get(

            "password"

        )


        users=load_users()


        for user in users:

            if (

                user[
                    "username"
                ]

                .lower()

                ==

                username.lower()

            ):

                if check_password_hash(

                    user[
                        "password_hash"
                    ],

                    password

                ):

                    session[

                        "user_id"

                    ]=(

                        user[
                            "user_id"
                        ]

                    )

                    session[

                        "username"

                    ]=(

                        username

                    )

                    return redirect(

                        "/"

                    )


        return (

            "Invalid login"

        )


    return render_template(

        "login.html"

    )


# ==========================
# LOGOUT
# ==========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(

        "/login"

    )


# ==========================
# HOME
# ==========================

@app.route("/")
def index():

    return render_template(

        "index.html",

        username=session[
            "username"
        ]

    )


# ==========================
# PROFILE
# ==========================

@app.route("/profile")
def profile():

    history=load_json(

        f"data/users/{session['user_id']}/scan_history.json",

        []

    )

    return render_template(

        "profile.html",

        history=history,

        username=session[
            "username"
        ]

    )


# ==========================
# SCAN
# ==========================

@app.route(

"/scan",

methods=["POST"]

)

def scan():

    domain=request.form.get(

        "domain"

    )

    mode=request.form.get(

        "mode",

        "simple"

    )

    consent=request.form.get(

        "consent"

    )


    if consent!="on":

        return (

            "Authorization required"

        )


    domain=normalize_domain(

        domain

    )


    if not validate_domain(

        domain

    ):

        return (

            "Invalid domain"

        )


    print(

        f"[SCAN] {domain}"

    )


    try:

        dns_and_tech_scan(

            domain

        )

        vuln_scan(

            domain

        )


        if mode=="complex":

            with ThreadPoolExecutor(

                max_workers=3

            ) as executor:

                executor.submit(

                    enumerate_subdomains,

                    domain

                )

                executor.submit(

                    port_scan,

                    domain,

                    True

                )

                executor.submit(

                    dir_bruteforce,

                    domain

                )


        risk_data=(

            generate_risk_report(

                domain

            )

        )


        vuln_data=load_json(

            f"data/results/{domain}_vulnerabilities.json",

            {

                "findings":[]

            }

        )


        explanations=(

            generate_risk_explanation(

                vuln_data,

                risk_data

            )

        )


        compliance=(

            evaluate_compliance(

                vuln_data

            )

        )


        recommendations=(

            generate_recommendations(

                vuln_data

            )

        )


        posture=(

            calculate_security_posture(

                vuln_data,

                risk_data,

                compliance

            )

        )


        report_folder=(

            f"data/users/{session['user_id']}/reports"

        )


        generate_pdf_report(

            domain,

            mode,

            risk_data,

            vuln_data,

            report_folder

        )


        history_path=(

            f"data/users/{session['user_id']}/scan_history.json"

        )


        history=load_json(

            history_path,

            []

        )


        history.insert(

            0,

            {

                "domain":domain,

                "mode":mode,

                "severity":

                risk_data[
                    "overall_severity"
                ],

                "risk_score":

                risk_data[
                    "total_risk_score"
                ],

                "time":

                datetime.now()

                .strftime(

                    "%Y-%m-%d %H:%M"

                ),

                "report":

                f"{domain}_security_report.pdf"

            }

        )


        history=history[:50]


        save_json(

            history_path,

            history

        )


        return render_template(

            "result.html",

            domain=domain,

            mode=mode,

            risk_score=

            risk_data[
                "total_risk_score"
            ],

            severity=

            risk_data[
                "overall_severity"
            ],

            vuln_count=

            len(

                risk_data[
                    "findings"
                ]

            ),

            explanations=

            explanations,

            compliance=

            compliance,

            recommendations=

            recommendations,

            posture=

            posture

        )


    except Exception as e:

        print(

            f"[SCAN ERROR] {e}"

        )

        return (

            f"Scan Failed: {e}"

        )


# ==========================
# DOWNLOAD
# ==========================

@app.route(

"/download/<path:filename>"

)

def download(filename):

    filename=secure_filename(

        filename

    )

    folder=(

        f"data/users/{session['user_id']}/reports"

    )

    return send_from_directory(

        folder,

        filename,

        as_attachment=True

    )


# ==========================
# MAIN
# ==========================

if __name__=="__main__":

    os.makedirs(

        "data/results",

        exist_ok=True

    )

    os.makedirs(

        "data/users",

        exist_ok=True

    )

    if __name__=="__main__":

     port=int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )