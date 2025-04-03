from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
import re
import user_management as dbHandler
import bcrypt

password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
app = Flask(__name__)

def set_csp_header():
    response = app.make_response()
    response.headers['Content-Security-Policy'] = (
        "base-uri 'self'; default-src 'self'; style-src 'self'; script-src 'self'; img-src *; media-src 'self'; font-src 'self'; object-src 'self'; child-src 'self'; connect-src 'self'; worker-src 'self'; report-uri /csp_report; frame-ancestors 'none'; form-action 'self'; frame-src 'none';"
    )
    return response

@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]

                
        if not password_regex.match(password): #express not correct password
            
            return render_template("/signup.html") # If password is invalid, sent back to try again
        
        hash_password = bcrypt.checkpw(password.encode('utf-8'), bcrypt.gensalt())#generate hash and salt

        dbHandler.insertUser(username, hash_password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])

def home():
     if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
     if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        storehash = dbHandler.retrieve(username)#take store hash out to retrieve i think
        if storehash and bcrypt.checkpw(password.encode('utf-8'), storehash):#revert to check password
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=True)
        else:
            return render_template("/index.html", error="Try again due to invalid password")
     else:
        return render_template("/index.html")

@app.route("/csp_report", methods=["POST"])
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
