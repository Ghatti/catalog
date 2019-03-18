# PYTHON CATALOG APP # 

This is a class assignment for the Udacity Fullstack Web Developer nanodegree.

## Usage ##

To run the script, you first need to have _python 3_ installed. You can [get python here](https://www.python.org/downloads/). Choose the correct version for your system and follow the installer instructions.

You will also need to get _virtual box_ using [this link](https://www.virtualbox.org/wiki/Downloads) and _vagrant_ using [this one](https://www.vagrantup.com/downloads.html). Be sure to pick the correct version for your system and follow the installation instructions.

Once you have both installed, download the virtual machine configuration files (which contains the database that will be used by the script) using [this link](https://d17h27t6h515a5.cloudfront.net/topher/2017/June/5948287e_fsnd-virtual-machine/fsnd-virtual-machine.zip) or by cloning [this repository](https://github.com/udacity/fullstack-nanodegree-vm).

Unzip the configuration files on a convenient directory and move to them using a shell, then move to the directory vagrant and execute the command `vagrant up`. After it is done, execute `vagrant ssh`.

If everything goes right, you will have to move to the _/vagrant_ directory inside your virtual machine. This directory is shared with your computer. The script of this repository must be downloaded and stored on the /vagrant directory.

You will also need to set the views listed on the next topic.

Once everything is done, move to the directory you store this script (remember it must be inside the /vagrant directory) and run the command:

`python3 project.py`

The server will start running and you will be able to make requests using curl, postman or a browser.

## Files ##

### project.py ###

This is the main script file. It is responsible for:

- Connecting to the database
- Running the server
- Executing the queries
- Responding the requests
- Taking care of authentication and authorization

### database_setup.py ###

This file contains the setup to use sqlalchemy. It has 3 models:

- User:

This model has an id and must have a name and an email. It can also have a picture, a google_id and a password_hash. The password_hash is used when registering and signing in locally, while the google_id is used when the google sign in is utilized. 

This model also has an admin property that defaults to false and is used for authorization purposes.

- Category:

This model represents the categories of products. It consists of an id and a name only.

- Item:

This model represents the products. It has an id. It must have a name, a description, a category id (the id of the category it belongs to), an user id (the id of the user that created it).

It also has an creation_date and a last_edited field. The first one is filled when the item is created, while the last one is update every time the item is modified.

### Templates folder ###

Contains all the html templates used by the server

### Static folder ###

Contains the css files to style the html pages.

## HTML endpoints ##

This project has the following html endpoints:

- "/" or "/catalog" - The home page - **Public**
- "/items/new/" - The item creation page - **Restricted**
- "/categories/new/" - The category creation page - **Restricted**
- "/catalog/<int:category_id>/" - This page allows the user to see a list of items that belong to a category - **Public**
- "/catalog/items/<int:item_id>/" - This page allows the user to see detailed data about an item - **Public**
- "/catalog/items/<int:item_id>/edit/" - Item edition page - **Restricted**
- "/catalog/items/<int:item_id>/delete/" - Item deletion page - **Restricted**

### Public endpoints ###

The endpoints marked as public can be viewed by anyone, even users not registered. The pages might render differently if the user is registered: they are going to show links to restricted resources that the user can visit.

### Restricted endpoints ###

The endpoints marked as restricted cannot be visited by users that are not signed in. Additional restrictions can apply. The restrictions follow two rules:

- Item and Category creation can be visited by any users that are signed in.
- Item edition and deletion endpoints can only be visited by the users that created the item edited/deleted by the endpoint or by the website administrators. 

### Absence of category management endpoints ###

The deletion of categories can only be done by the website administrators via API. There are no html pages for these operations.

### Authentication methods ###

Users using the html endpoints can register and sign in with google sign in.


## API endpoints ##

The API endpoints can be used by authenticated users via curl requests. They must register locally and can supply a username:password pair of credentials or a token.

### Registering to use the API ###

To register an user, make a POST request to the "/users/" endpoint, containing a json with the following parameters:

`{
    "username": string,
    "password": string,
    "email": string
}`

If successfull, the api will return the username that was supplied. 

Usernames must be unique.

### Getting a token ###

To get a token, make a GET request via curl to the "/token/" endpoint. You must supply a username:password pair of credentials.

If successful, the API will return a token.

### Using the API ###

- "/api/categories/" endpoint:

This endpoint allows the user to do a GET request to get a list of all categories.

It also allows the user to do a POST request to create a category. The request must send a name via json:

`{
    "name": string
}` 

There is also a DELETE operation that can only be used by Administrators. It deletes all categories (and all items inside them)

- "/api/categories/<int:category_id>/"

This endpoint allows the user to do a GET request to get a list of all items that belong to the category <int:category_id>.

There is also a DELETE operation that can only be used by administrators. This operation deletes the chosen category and all items that belong to it.

- "/api/items/"

This endpoint allows the user to do a GET request to get a list of all registered items.

It also allows the user to do a POST request to create an item. The request must send a name, a description and a category via json:

`{
    "name": string,
    "description": string,
    "category": string
}` 

There is also a DELETE operation that can only be used by administrators. This operation deletes all registered items.

- "/api/items/<int:item_id>/"

This endpoint allows the user to do a GET request the data from an item.

It also allows the user to do a PUT request to edit an item. The request must send a name or a description or a category via json:

`{
    "name": string,
    "description": string,
    "category": string
}` 

The supplied parameters are edited, while the others are left untouched.

There is also a DELETE operation that can only be used by administrators or by the user that created the item. This operation deletes the chosen item.

The three operations (GET, PUT and DELETE) are performed on the item defined by the id <int:item_id> on the url.