# 2019-Python-vtun547

## How to run on the University Linux Desktops

1. Clone this repository into a folder of your choice
2. Navigate to the root directory of this repository called '2019-Python-vtun547'
3. Ensure python3, cherrypy, jinja2, and nacl are installed. 
4. Type 'python3 mainApp.py' in terminal
5. Open a web browser and type 'http://0.0.0.0:10014'

## Logging in to the client

The login screen has three required text inputs: username, password, and secret box password. The username and password behave as normal with upi as the username and github username underscore student id number as the password. The secret box password is used for encrypting and decrypting private data. If a user already has private data saved on the login server, they must enter their secret password that they previously created or 'incorrect secret password' will be shown and they will not be logged in. If they have not yet added any private data, they can enter any password into the secret password box and this will be set as their password for decrypting private data. This new secret password must be remembered as they will have to use it to log in on all future attempts.

## Compatable Users

rhar768 and lche982 private keys can be loaded from private data on my client and my private data can be loaded on theirs. All of my other functionality also works between our clients.
