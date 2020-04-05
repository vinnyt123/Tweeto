# Tweeto

## Overview

Tweeto is a social media application created using the CherryPy web framework for Python3.

The application connected to a central server which provided an API returning addresses and public keys of other users. My application, as well as the applications of classmates, hosted their own servers with APIs that followed a communication protocol we developed as a group. This meant once we had retrieved IP addresses of classmates from the central server, we could send messages to eachother entirely peer-to-peer.

Messages were encrypted against the public key of the recipient before being sent, and were decrypted using the corresponding private key upon recieving the message. Public/private key pair generation as well as encryption and decryption functions were provided by the PyNacl python module. Messages and public broadcasts were saved when recieved, to a relational database file on our server, and queried using SQL, facilitated by the sqlite3 module for Python. 

HTML, CSS, and Javascript were also used for creation of the user interface with the help of the Jinja2 python module for page templating. JQuery was used for Ajax refreshing of the chat windows and online users lists.

Note: the application no longer runs due to the central server that was hosted by our lecturer being taken down.

## How to run on the University Linux Desktops

1. Clone this repository into a folder of your choice
2. Navigate to the root directory of this repository called '2019-Python-vtun547'
3. Ensure python3, cherrypy, jinja2, and nacl are installed. 
4. Type 'python3 mainApp.py' in terminal
5. Open a web browser and type 'http://0.0.0.0:10014'

## Logging in to the client

The login screen has three required text inputs: username, password, and secret box password. The username and password behave as normal with upi as the username and github username underscore student id number as the password. The secret box password is used for encrypting and decrypting private data. If a user already has private data saved on the login server, they must enter their secret password that they previously created or 'incorrect secret password' will be shown and they will not be logged in. If they have not yet added any private data, they can enter any password into the secret password box and this will be set as their password for decrypting private data. This new secret password must be remembered as they will have to use it to log in on all future attempts.
