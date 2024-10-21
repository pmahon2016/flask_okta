from flask import Flask, render_template, url_for, request, redirect, g
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SubmitField
from werkzeug.utils import secure_filename
from flask_oidc import OpenIDConnect
from okta import UsersClient  # make sure the version is correct {pip install okta==0.0.4}
from oauth2client.client import OAuth2Credentials  # required for access tokens and token ID
import os
import hashlib  # hashing library
import json

app = Flask(__name__)  # Flask global object

# --------THIS SECTION IF FOR THE OPENID CONNECT CONFIGS--------------
app.config["OIDC_CLIENT_SECRETS"] = "client_secrets.json"
app.config["OIDC_COOKIE_SECURE"] = False
app.config["OIDC_CALLBACK_ROUTE"] = "/oidc/callback"
app.config["OIDC_SCOPES"] = ["openid", "email", "profile"]
app.config['SECRET_KEY'] = '\xffI\x18M\x977\x19,\xd2|\x7f\xbc\xf6J\xc4%'
app.config["OIDC_ID_TOKEN_COOKIE_NAME"] = "oidc_token"
oidc = OpenIDConnect(app)
okta_client = UsersClient("https://YOUR_DOMAIN/",
                          "ACCESS_TOKEN")  # change the auth code to yours

hashes = {}


# uses the g global object to the user info and have it available in the app context before a form request
@app.before_request
def before_request():
    if oidc.user_loggedin:
        g.user = okta_client.get_user(oidc.user_getfield("sub"))
        print((g.user.profile.mobilePhone))
    else:
        g.user = None


class FileUpload(FlaskForm):  # class to inherit from Flaskform lib to get input fields need in form
    file = FileField(validators=[FileRequired()])
    submit = SubmitField('Get Hash')


@app.route('/', methods=['GET', 'POST'])  # main endpoint to load the form w/ radio buttons options, file upload
def forms():
    form = FileUpload()  # instance of class created above to inherit from Flaskform
    userdb = {}
    if not os.path.exists('uploads/'):
        os.mkdir('uploads/')  # create an "uploads" directory if none exist
    if form.validate_on_submit():  # WTF validation check
        filename = secure_filename(form.file.data.filename)

        form.file.data.save('uploads/' + filename)  # save uploaded file in uploads to open later and get hash value

        with open('uploads/' + filename, 'rb') as f:  # open as binary. Get the algo (from radio buttons) and hash
            fileread = f.read()
            option = request.form['exampleRadios']
            if option == 'SHA-256':
                hash_value = hashlib.sha256(fileread).hexdigest()
            elif option == 'SHA-384':
                hash_value = hashlib.sha384(fileread).hexdigest()
            elif option == 'SHA-512':
                hash_value = hashlib.sha512(fileread).hexdigest()
            elif option == 'MD5':
                hash_value = hashlib.md5(fileread).hexdigest()
            else:
                print("No Algo Provided")  # debugging statement
        if g.user:
            if os.path.isfile('hashes.json'):  # open the json file and load into userdb
                with open('hashes.json', 'r') as jf:
                    userdb = json.load(jf)
            hash_value = option + ":" + hash_value  # include the algo with the hash value
            if g.user.profile.email in userdb.keys():  # if the user is already in the hashes db, just append
                userdb[g.user.profile.email].append({filename: hash_value})
            else:
                userdb[g.user.profile.email] = [{filename: hash_value}]  # if not create

            with open('hashes.json', 'w') as fp:  # open the json file to add updates and format (indent)
                json.dump(userdb, fp, indent=4)

        return render_template('output.html', filename=filename, algo=option, hashstring=hash_value, p_requests=userdb)

    return render_template('form.html', form=form)  # if anything in the forms def fails - reload the initial page


@app.route("/userprofile")  # this endpoint is used to display info about the user
@oidc.require_login
def userprofile():
    mytoken = oidc.get_access_token()
    if mytoken:
        info = oidc.user_getinfo(['sub'])  # if the token is expired, this will be "none" so to prevent an error...
    else:
        mytoken = ' Expired'

    try:
        id_token_jwt = OAuth2Credentials.from_json(oidc.credentials_store[info.get('sub')]).id_token_jwt
    except:
        id_token_jwt = ' Expired'
    return render_template("userprofile.html", token=mytoken, tokenid=id_token_jwt)


@app.route("/login")
@oidc.require_login  # this endpoint is used to get the user to login and redirect him/her back to the forms page
def login():
    return redirect(url_for("forms"))


"""logout endpoint below. Note that if you click the login button after logging out, the same user will
login due to Single Sign-on. to logout the user and login another user, code would need to be added here or clear the
Browser cache."""


@app.route("/logout")
def logout():
    oidc.logout()
    return redirect(url_for("forms"))


if __name__ == '__main__':
    app.run(host="0.0.0.0",port=5000, debug=True
            )
