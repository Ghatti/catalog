from flask import (Flask, request, jsonify, abort, render_template, redirect,
                   url_for, flash, make_response, g)
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth
from sqlalchemy import create_engine, exists, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from datetime import datetime
import random
import string
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
import httplib2
import json
import requests
import os

CLIENT_ID = json.loads(open("client_secrets.json", "r")
                       .read())["web"]["client_id"]

app = Flask(__name__)
app.secret_key = "thisisassecretasitgets2%"
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

auth = HTTPBasicAuth()

CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = ["openid", "profile", "email"]
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'


# Local signup endpoints
@app.route('/users/', methods=['POST'])
def new_user():
    session = DBSession()
    username = request.json.get("username")
    password = request.json.get("password")
    email = request.json.get("email")

    if username is None or password is None or email is None:
        abort(400, "You need to supply an username and a password")
    if session.query(User).filter_by(name=username).first() is not None:
        abort(400, "Username already used")

    user = User(name=username, email=email)
    user.hash_password(password)
    session.add(user)
    session.commit()

    username = user.name

    session.close()
    return jsonify({"username": username}, 201)


# Function to verify if credentials  were supplied
# (username + password or token)
@auth.verify_password
def verify_password(username_or_token, password):

    if request.method == "GET":
        return True

    session = DBSession()
    user_id = User.verify_auth_token(username_or_token)

    if user_id:
        user = session.query(User).filter_by(id=user_id).first()
    else:
        user = session.query(User).filter_by(name=username_or_token).first()

        if not user or not user.verify_password(password):
            return False

    login_session["userId"] = user.id
    login_session["admin"] = user.admin
    session.close()
    return True


# Endpoint to get a token
@app.route('/token/')
@auth.login_required
def get_auth_token():

    session = DBSession()
    user = session.query(User).filter_by(id=login_session["userId"]).first()

    token = user.generate_auth_token()

    session.close()
    return jsonify({"token": token.decode("ascii")})


# Google signup endpoints
@app.route("/gconnect", methods=["POST"])
def gconnect():

    token = request.data

    if request.args.get("state") != login_session["state"]:
        response = make_response(json.dumps("Invalid state content"), 401)
        response.headers["Content-Type"] = "application/json"
        return response

    idinfo = id_token.verify_oauth2_token(token,
                                          grequests.Request(),
                                          CLIENT_ID)
    if idinfo['iss'] not in ['accounts.google.com',
                             'https://accounts.google.com']:
        raise ValueError('Wrong issuer.')
    google_id = idinfo['sub']

    userId = getUserID(idinfo["email"])

    if userId is None:
        userId = createUser(idinfo)

    login_session["userId"] = userId
    login_session["credentials"] = token
    return redirect(url_for("showHome"))


@app.route("/gdisconnect")
def gdisconnect():

    userId = login_session.get("userId")

    if userId is None:
        response = make_response(json.dumps("Current user not connected."),
                                 401)
        response.headers["Content-Type"] = "application/json"
        return response

    requests.post('https://accounts.google.com/o/oauth2/revoke',
                  params={'token': login_session["credentials"]},
                  headers={'content-type': 'application/x-www-form-urlencoded'})

    del login_session["userId"]
    del login_session["credentials"]

    return redirect(url_for("showHome"))


# User Helper Functions
def createUser(idinfo):
    session = DBSession()

    newUser = User(name=idinfo['name'], email=idinfo['email'],
                   picture=idinfo['picture'], google_id=idinfo['sub'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=idinfo['email']).one()
    user_id = user.id
    session.close()
    return user_id


def getUserID(email):
    session = DBSession()

    user_id = session.query(User).filter_by(email=email).one().id
    session.close()
    return user_id


# Template endpoint routes

# Home endpoint: shows all categories and the 5 latest created items
@app.route("/")
@app.route("/catalog/")
def showHome():
    userId = login_session.get("userId")

    state = "".join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session["state"] = state

    session = DBSession()
    categories = session.query(Category).all()
    latest = session.query(Item).order_by(desc(Item.creation_date)).limit(5)
    session.close()

    return render_template("home.html", categories=categories,
                           latest=latest, userId=userId, STATE=state)


# Item creation endpoint. User must be logged in.
@app.route("/catalog/items/new/", methods=["GET", "POST"])
def newItem():
    userId = login_session.get("userId")

    if userId is None:
        flash("User is not connected")
        return redirect(url_for("showHome"))

    session = DBSession()
    categories = session.query(Category).all()

    if request.method == "GET":
        return render_template("newitem.html", categories=categories)

    if request.method == "POST":

        name = request.form["name"]
        description = request.form["description"]
        category = request.form["category"]

        if name and description and category:
            if session.query(Item).filter_by(name=name).first():
                return abort(400, "Item already exists")
        else:
            return abort(400,
                         """The name, description and category parameters
                         must be supplied""")

        categoryData = session.query(Category).filter_by(name=category).first()

        if not category:
            return abort(400, "Category does not exist")

        newItem = Item(
            name=name,
            description=description,
            category_id=categoryData.id,
            creation_date=datetime.now(),
            last_edited=datetime.now(),
            user_id=userId
        )

        session.add(newItem)
        session.commit()
        session.close()

        flash("New item %s created!" % name)
        return redirect(url_for("showHome"))


# Category creation endpoint. User must be logged in.
@app.route("/catalog/categories/new/", methods=["GET", "POST"])
def newCategory():
    userId = login_session.get("userId")

    if userId is None:
        flash("User is not connected")
        return redirect(url_for("showHome"))

    if request.method == "GET":
        return render_template("newcategory.html")

    if request.method == "POST":

        session = DBSession()

        if not request.form["name"]:
            return abort(400, "No category name provided")

        if session.query(Category).filter_by(name=request.form["name"]).first():
            return abort(400, "Category already exists")

        newCategory = Category(name=request.form["name"])

        session.add(newCategory)
        session.commit()
        session.close()
        flash("New category %s created!" % request.form["name"])
        return redirect(url_for("showHome"))


# Show all items of a category
@app.route("/catalog/<int:category_id>/")
def showCategory(category_id):
    userId = login_session.get("userId")
    session = DBSession()
    categoryData = session.query(Category).filter_by(id=category_id).first()

    if not categoryData:
        return abort(404)

    items = session.query(Item).filter_by(category_id=category_id)

    session.close()
    return render_template("category.html",
                           categoryData=categoryData,
                           items=items,
                           userId=userId)


# Show the available information for an item
@app.route("/catalog/items/<int:item_id>/")
def showItem(item_id):
    userId = login_session.get("userId")
    session = DBSession()
    itemData = session.query(Item).filter_by(id=item_id).first()

    if not itemData:
        return abort(404)

    categoryData = session.query(Category).filter_by(id=itemData.category_id).first()

    session.close()
    return render_template("item.html",
                           categoryData=categoryData,
                           itemData=itemData,
                           userId=userId)


# Edit an item. Only usable by the user that created the item or an admin.
@app.route("/catalog/items/<int:item_id>/edit/", methods=["GET", "POST"])
def editItem(item_id):
    userId = login_session.get("userId")

    if userId is None:
        flash("User is not connected")
        return redirect(url_for("showHome"))

    session = DBSession()
    itemData = session.query(Item).filter_by(id=item_id).first()

    if not itemData:
        return abort(404)

    if itemData.user_id != userId:
        flash("User cannot edit item %s" % itemData.name)
        return redirect(url_for("showHome"))

    if request.method == "GET":

        categories = session.query(Category).all()
        itemCategory = session.query(Category).filter_by(id=itemData.category_id).first()
        session.close()
        return render_template("edititem.html",
                               categories=categories,
                               itemData=itemData,
                               itemCategory=itemCategory.name)

    if request.method == "POST":

        newName = request.form["name"]
        newDesc = request.form["description"]
        newCat = request.form["category"]

        if not newName and not newDesc and not newCat:
            flash("Item not edited")
            return redirect(url_for("showItem", item_id=item_id))

        if newName != itemData.name and session.query(Item).filter_by(name=newName).first():
            return abort(400, "This item name has already been used")

        if newCat:
            newCategory = session.query(Category).filter_by(name=newCat).first()

        if newName:
            itemData.name = newName
        if newDesc:
            itemData.description = newDesc
        if newCat:
            itemData.category_id = newCategory.id

        itemData.last_edited = datetime.now()

        session.add(itemData)
        session.commit()

        # holds the category id before closing the session,
        # so url_for can be used
        category_id = itemData.category_id
        flash("Item successfully edited")
        session.close()
        return redirect(url_for("showItem",
                        category_id=category_id, item_id=item_id))


# Delete an item. Only usable by the user that created the item or an admin.
@app.route("/catalog/items/<int:item_id>/delete/", methods=["GET", "POST"])
def deleteItem(item_id):
    userId = login_session.get("userId")

    if userId is None:
        flash("User is not connected")
        return redirect(url_for("showHome"))

    session = DBSession()
    itemData = session.query(Item).filter_by(id=item_id).first()

    if not itemData:
        return abort(404)

    if itemData.user_id != userId:
        flash("User cannot delete item %s" % itemData.name)
        return redirect(url_for("showHome"))

    if request.method == "GET":
        session.close()
        return render_template("deleteitem.html", itemData=itemData)

    if request.method == "POST":

        category_id = itemData.category_id

        session.delete(itemData)
        session.commit()
        session.close()

        flash("Item %s successfully deleted" % itemData.name)
        return redirect(url_for("showCategory", category_id=category_id))


# API Routes

# Endpoint for operations that affect all categories or to create a category
@app.route("/api/categories/", methods=["GET", "POST", "DELETE"])
@auth.login_required
def apiAllCategories():

    session = DBSession()
    # Get all categories in json format
    if request.method == "GET":

        categories = session.query(Category).all()
        session.close()
        return jsonify(categories=[category.serialize
                       for category in categories])
    # Add a new category, receiving data in json format
    # from the request's body.
    if request.method == "POST":

        if not login_session.userId:
            return abort(401, """Only registered users
                         can perform this operation""")

        body = request.get_json()

        if session.query(Category).filter_by(name=body["name"]).first():
            return abort(400, "Category already exists")

        newCategory = Category(name=body["name"])

        session.add(newCategory)
        session.commit()
        session.close()
        return "New Category %s created" % body["name"]

    # Deletes all categories. Also deletes all items as a consequence.
    if request.method == "DELETE":

        if not login_session.admin:
            return abort(401, "Only administrators can perform this operation")

        session.query(Category).delete()
        session.query(Item).delete()
        session.commit()
        return "All categories and items deleted"


# Retrieves or deletes the items from one category
@app.route("/api/categories/<int:category_id>/", methods=["GET", "DELETE"])
@auth.login_required
def apiManageCategory(category_id):
    session = DBSession()

    if request.method == "GET":

        if not session.query(Category).filter_by(id=category_id).first():
            return abort(400, "Category does not exist")

        categoryData = session.query(Item).filter_by(category_id=category_id).all()
        session.close()
        return jsonify([item.serialize for item in categoryData])

    if request.method == "DELETE":

        if not login_session.admin:
            return abort(401, "Only administrators can perform this operation")

        if not session.query(Category).filter_by(id=category_id).first():
            abort(400, "Category does not exist")

        session.query(Item).filter_by(category_id=category_id).delete()
        session.query(Category).filter_by(id=category_id).delete()
        session.commit()
        session.close()
        return "Category deleted"


# Endpoint for operations that affects all items or to create a new item
@app.route("/api/items/", methods=["GET", "POST", "DELETE"])
@auth.login_required
def apiAllItems():

    session = DBSession()
    # Get all items in json format
    if request.method == "GET":

        items = session.query(Item).all()
        session.close()
        return jsonify(items=[item.serialize for item in items])

    # Add a new item, receiving data in json format from the request's body
    if request.method == "POST":

        body = request.get_json()

        if (body.get("name") and body.get("description") and
                body.get("category")):

            if session.query(Item).filter_by(name=body["name"]).first():
                return abort(400, "Item already exists")
        else:
            return abort(400, """The name, description and category parameters
                        must be supplied""")

        category = session.query(Category).filter_by(name=body["category"]).first()

        if not category:
            return abort(400, "Category does not exist")

        newItem = Item(
            name=body["name"],
            description=body["description"],
            category_id=category.id,
            creation_date=datetime.now(),
            last_edited=datetime.now(),
            user_id=login_session["userId"]
        )

        session.add(newItem)
        session.commit()
        session.close()
        return "New item %s sucessfully created" % body["name"]

    # Deletes all items
    if request.method == "DELETE":

        if not login_session.admin:
            return "Only administrators can perform this operation"

        session.query(Item).delete()
        session.commit()
        session.close()
        return "All items were deleted"


# This endpoint allows an user to get,
# edit or delete information from one specific item
@app.route("/api/items/<int:item_id>/", methods=["GET", "PUT", "DELETE"])
@auth.login_required
def apiManageItem(item_id):

    session = DBSession()

    # Retrieves the the data of an item
    if request.method == "GET":

        if not session.query(Item).filter_by(id=item_id).first():
            return abort(400, "Item does not exist")

        itemData = session.query(Item).filter_by(id=item_id).first()
        session.close()
        return jsonify(item=itemData.serialize)

    # Edits an item. The item selected to edit is determined by the url,
    # the new item data is retrieved from the request's body
    if request.method == "PUT":

        body = request.get_json()

        itemData = session.query(Item).filter_by(id=item_id).first()

        if not itemData:
            return abort(400, "Item does not exist")

        if (itemData.user_id != login_session.get("userId") and not
                login_session.get("admin")):
            return abort(401, "You cannot edit this item")

        name = body.get("name")
        desc = body.get("description")
        category = body.get("category")

        if name:
            if session.query(Item).filter_by(name=name).first():
                return abort(400, "The new item name has already been used")
            itemData.name = name

        if desc:
            itemData.description = desc
        if category:

            catData = session.query(Category).filter_by(name=category).first()
            if not catData:
                session.rollback()
                return abort(400, "The new category does not exist yet")
            itemData.category_id = catData.id

        itemData.last_edited = datetime.now()

        session.add(itemData)
        session.commit()
        session.close()

        return "Item sucessfully edited"

    # Deletes an item
    if request.method == "DELETE":

        item = session.query(Item).filter_by(id=item_id).first()
        if not item:
            return abort(400, "The requested item does not exist")

        if item.user_id != login_session.get("userId") and not login_session.get("admin"):
            return abort(401, "You cannot edit this item")

        session.delete(item)
        session.commit()
        session.close()
        return "Deleted item %s" % (item.name)


if __name__ == "__main__":
    app.debug = True
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='0.0.0.0', port=5000)
