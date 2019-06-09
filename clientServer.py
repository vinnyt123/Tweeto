import cherrypy
import urllib.request
import json
import base64
import nacl.pwhash
import nacl.secret
import nacl.encoding
import nacl.signing
import time
import database
import base64
import threading
from database import Database
from jinja2 import Environment, FileSystemLoader
import socket

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

loginServerAPIURL = "http://cs302.kiwi.land/api/"

file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)

port = ":10014"

class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self, bad_attempt=-1):
        try:
            cherrypy.session['username']

            cherrypy.session['database'] = Database()

            template = env.get_template('broadcasts.html')

            broadcasts = cherrypy.session['database'].getAllBroadcasts()

            return template.render(broadcasts=broadcasts, username = cherrypy.session['username'], status = cherrypy.session['status'].title())

        except KeyError: #There is no username
            raise cherrypy.HTTPRedirect('login')
    
    @cherrypy.expose
    def messages(self):
        try:
            template = env.get_template('messages.html')

            list_users_response = urlRequest(loginServerAPIURL + "list_users", "", True)
            
            usersList = list_users_response['users']

            cherrypy.session['online_users'] = usersList

            return template.render(users=usersList, username = cherrypy.session['username'], status = cherrypy.session['status'].title())
        except KeyError:
            raise cherrypy.HTTPRedirect("/")

    @cherrypy.expose
    def online_users(self):
        try:
            template = env.get_template('online_users.html')
            list_users_response = urlRequest(loginServerAPIURL + "list_users", "", True)
            
            usersList = list_users_response['users']

            return template.render(users=usersList)
        except KeyError:
            raise cherrypy.HTTPRedirect("/")


    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        if bad_attempt == '1':
            Page += "<font color='red'>Invalid username/password!</font>"
        if bad_attempt == '2':
            Page += "<font color='red'>Invalid secret key password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += 'Secret Box Password: <input type="text" name="secret_password">'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, secret_password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password, secret_password)
        if error == 0:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            #autoReport(cherrypy.session['pubkey'])
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt={}'.format(error))

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        print("signing out")
        try:
            (IP_address, connection_location) = detectIPAddressAndConnectionLocation()
            payload = {
                "connection_address": IP_address + port,
                "connection_location": connection_location,
                "incoming_pubkey": cherrypy.session['pubkey'],
                "status" : "offline"
            }
            reportResponse = urlRequest(loginServerAPIURL + "report", payload, False)
        except KeyError as e:
            raise cherrypy.HTTPRedirect('/')

        username = cherrypy.session.get('username')
        if username is None:
            print("XXXXX")
            pass
        else:
            cherrypy.lib.sessions.expire()
            print("EXPIRED")
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def sendbroadcast(self, message):

        currentUnixTime = time.time()
        payload = {
            "loginserver_record": cherrypy.session["loginserver_record"],
            "message": message,
            "sender_created_at" : str(currentUnixTime),
            "signature" : createSignature(str(cherrypy.session["loginserver_record"] + message + str(currentUnixTime)))
        }

        #urlRequest("http://" + myIP + "/api/rx_broadcast", payload, False)
        sendToAllOnlineUsers("rx_broadcast", payload, False)

        raise cherrypy.HTTPRedirect('/?bad_attempt=0')

    @cherrypy.expose
    def getBroadcasts(self):
        try:
            broadcasts = cherrypy.session['database'].getAllBroadcasts()
            template = env.get_template('broadcasts_list.html')

            return template.render(broadcasts=broadcasts)
        except KeyError:
            print("not logged in")
            



    @cherrypy.expose
    @cherrypy.tools.json_out()
    def send_private_message(self, username, message):
        username = username.strip()
        string_time = str(time.time())

        for user in cherrypy.session['online_users']:
            if user['username'] == username:
                encrypted_message = encrypt_message(user['incoming_pubkey'], message)
                encrypted_message_with_my_pubkey = encrypt_message(cherrypy.session['pubkey'], message)
                signature = createSignature(cherrypy.session['loginserver_record'] + user['incoming_pubkey'] + user['username'] + encrypted_message + string_time)
                payload = {
                    "loginserver_record" : cherrypy.session['loginserver_record'],
                    "target_pubkey" : user['incoming_pubkey'],
                    "target_username" : user['username'],
                    "encrypted_message" : encrypted_message,
                    "sender_created_at" : string_time,
                    "signature" : signature
                }
                response = urlRequest("http://" + user['connection_address'] + "/api/rx_privatemessage", payload, False)['response']
                if response == 'ok' and username != cherrypy.session['username']:
                    databaseTuple = (user['username'], cherrypy.session['username'], string_time, encrypted_message_with_my_pubkey, signature, cherrypy.session['pubkey'], cherrypy.session['loginserver_record'])
                    cherrypy.session['database'].insertMessage(databaseTuple)
                return response

    @cherrypy.expose
    def getMessageHistory(self, userName):
        try:
            template = env.get_template('chatMessages.html')
            userName = userName.strip()
            messages = cherrypy.session['database'].getMessageHistory(userName, cherrypy.session['username'], cherrypy.session['pubkey'])
            for message in messages:
                message['message'] = decrypt_message(message['message'])

            rendered = template.render(messages=messages, username=cherrypy.session['username'])
            print(rendered)
            return rendered
        except KeyError:
            raise cherrypy.HTTPRedirect("/")

    @cherrypy.expose
    def report(self):
        try:
            (IP_address, connection_location) = detectIPAddressAndConnectionLocation()
            payload = {
                "connection_address": IP_address + port,
                "connection_location": connection_location,
                "incoming_pubkey": cherrypy.session['pubkey']
            }
            reportResponse = urlRequest(loginServerAPIURL + "report", payload, False)
            return reportResponse['response']
        except KeyError:
            raise cherrypy.HTTPRedirect('/login')

    @cherrypy.expose
    def statusReport(self, status):
        try:
            (IP_address, connection_location) = detectIPAddressAndConnectionLocation()
            payload = {
                "connection_address": IP_address + port,
                "connection_location": connection_location,
                "incoming_pubkey": cherrypy.session['pubkey'],
                "status" : status
            }
            reportResponse = urlRequest(loginServerAPIURL + "report", payload, False)
            cherrypy.session['status'] = status
            return reportResponse['response']
        except KeyError:
            print("XXXXXXXXXXXX REPORT FAILED " + reportResponse)
            raise cherrypy.HTTPRedirect('/login')
            return "Not logged in"
    
    @cherrypy.expose
    def pingCheck(self):
        try:
            (ip_address, connection_location) = detectIPAddressAndConnectionLocation()
            payload = {
                "my_time": str(time.time()),
                "connection_address": ip_address,
                "connection_location": connection_location 
            }

            sendToAllOnlineUsers('ping_check', payload, False)

            print("PING CHECKED")
            return "ok"
        except KeyError:
            raise cherrypy.HTTPRedirect("/")


            
            




                

    
       
            
        
###
### Functions only after here
###

def encrypt_message(pubkey_str, message):

    message = bytes(message.encode('utf-8'))
    pubkey_bytes_hex = pubkey_str.encode('utf-8')
    nacl_verify_key = nacl.signing.VerifyKey(pubkey_bytes_hex, encoder=nacl.encoding.HexEncoder)
    nacl_sealed_box_pubkey = nacl_verify_key.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(nacl_sealed_box_pubkey)
    encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
    encrypted_message = encrypted.decode('utf-8')
    return encrypted_message

def decrypt_message(encrypted_message):
    
    encrypted_message_bytes = encrypted_message.encode('utf-8')
    sealedbox_privatekey = cherrypy.session['signing_key'].to_curve25519_private_key()
    unseal_box = nacl.public.SealedBox(sealedbox_privatekey)
    decrypted_bytes = unseal_box.decrypt(encrypted_message_bytes, encoder=nacl.encoding.HexEncoder)

    return decrypted_bytes.decode('utf-8')

def authoriseUserLogin(username, password, secret_password):

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    cherrypy.session['headers'] = headers

    #Load new API
    load_new_apikey_response = urlRequest(loginServerAPIURL + "load_new_apikey", "", True)

    cherrypy.session['apikey'] = load_new_apikey_response['api_key']

    headers.pop('Authorization', None)
    headers['X-username'] = username
    headers['X-apikey'] = cherrypy.session['apikey']

    cherrypy.session['headers'] = headers

    #Ping number 1
    pingResponse = urlRequest(loginServerAPIURL + "ping", "", False)

    if (not(pingResponse['response'] == 'ok' and pingResponse['authentication'] == 'api-key')):
        print("ping1 response = " + str(pingResponse))
        return 1

    #Get private data
    get_privatedata_response = urlRequest(loginServerAPIURL + 'get_privatedata',"",True)

    if (get_privatedata_response['response'] == 'ok'):
        cherrypy.session['loginserver_record'] = get_privatedata_response['loginserver_record']
        if (decrypt_privatedata(get_privatedata_response['privatedata'], secret_password) == 1):
            return 2
    else:
        #Create new keypair
        createNewKeypair()

        #Add pubkey 
        payload = {
                "pubkey" : cherrypy.session['pubkey'],
                "username" : username,
                "signature" : createSignature(cherrypy.session['pubkey'] + username),
            }
        add_pubkey_response = urlRequest(loginServerAPIURL + "add_pubkey", payload, False)
        if (add_pubkey_response['response'] != 'ok'):
            print("add_pubkey response = " + str(add_pubkey_response))
            return 1

        cherrypy.session['loginserver_record'] = add_pubkey_response['loginserver_record']
        #Add privatedata
        if (add_privatedata(secret_password) != 0):
            return 1  
    
      
    #Ping number 2 to check keypair
    payload = {
        "pubkey" : cherrypy.session['pubkey'],
        "signature" : createSignature(cherrypy.session['pubkey']),
    }
    ping2Response = urlRequest(loginServerAPIURL + "ping", payload, False)

    if (not(ping2Response['signature'] == 'ok' and ping2Response['response'] == 'ok')):
        print("ping2 response = " + str(ping2Response))
        return 1

    (IP_address, connection_location) = detectIPAddressAndConnectionLocation()

    #Report
    payload = {
        "connection_address": IP_address + ":5000",
        "connection_location": connection_location,
        "incoming_pubkey": cherrypy.session['pubkey']
    }
    reportResponse = urlRequest(loginServerAPIURL + "report", payload, False)

    if (reportResponse['response'] != 'ok'):
        print ("report response = " + reportResponse)
        return 1
    else:
        cherrypy.session['status'] = 'online'
        return 0
          
    
        


#Utility method for requesting an API URL from Hammonds server. URL is everything after ...api/
def urlRequest(url, payload, isGET):
    payload = dictToBytes(payload)
    try:
        req = urllib.request.Request(url, data=payload, headers=cherrypy.session['headers'])
        if (url.endswith("rx_broadcast") or url.endswith("ping_check")):
            response = urllib.request.urlopen(req, timeout=0.2)
        else:
            response = urllib.request.urlopen(req, timeout=5)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        JSON_object = json.loads(data.decode(encoding))
        # print(JSON_object)
        return JSON_object
    except (urllib.error.HTTPError, urllib.error.URLError, socket.error) as error:
        return {"response" : "timeout"} 
    except KeyError:
        raise cherrypy.HTTPRedirect("/login")
    


def createNewKeypair():
    # Generate a new random signing key
    signing_key = nacl.signing.SigningKey.generate()
    cherrypy.session['signing_key'] = signing_key

    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    cherrypy.session['pubkey'] = pubkey_hex_str


def createSignature(string):
    message_bytes = bytes(string, encoding='utf-8')
    signed = cherrypy.session['signing_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    return signed.signature.decode('utf-8')


def sendToAllOnlineUsers(method, payload, isGET):
    list_users_response = urlRequest(loginServerAPIURL + "list_users", "", True)
    activeUsersList = list_users_response['users']
    cherrypy.session['online_users'] = activeUsersList

    for user in activeUsersList:
        urlRequest("http://" + user['connection_address'] + "/api/" + method, payload, isGET)

def add_privatedata(secret_password):

    secret_box = createSecretBox(secret_password)

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    signing_key_serializable = cherrypy.session['signing_key'].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    privatedata_dict = {
        'prikeys' : [signing_key_serializable],
        'test' : 'BOOOUSUSOSUOSOSOSOSUOSUOS'
    }

    privatedata_bytes = dictToBytes(privatedata_dict)

    encrypted_message = secret_box.encrypt(privatedata_bytes, nonce)

    encryped_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')

    currentTimeString = str(time.time())
    payload = {
        'privatedata' : encryped_message_base64,
        'loginserver_record' : cherrypy.session['loginserver_record'],
        'client_saved_at' : currentTimeString,
        'signature' : createSignature(encryped_message_base64 + cherrypy.session['loginserver_record'] + currentTimeString)
    }

    add_privatedata_response = urlRequest(loginServerAPIURL + 'add_privatedata',payload, True)

    if (add_privatedata_response['response'] == 'ok'):
        return 0
    else:
        print('error adding private data')
        return 1

def decrypt_privatedata(private_data_b64, secret_password):

    private_data_bytes = base64.b64decode(private_data_b64.encode('utf-8'))
    secret_box = createSecretBox(secret_password)
    try:
        unencrypted_private_data = secret_box.decrypt(private_data_bytes)
    except:
        return 1

    json_private_data = json.loads(unencrypted_private_data.decode('utf-8'))

    signing_key_hex = json_private_data['prikeys'][0]
    
    signing_key_bytes = signing_key_hex.encode('utf-8')

    cherrypy.session['signing_key'] = nacl.signing.SigningKey(signing_key_bytes, encoder=nacl.encoding.HexEncoder)

    pubkey_hex = cherrypy.session['signing_key'].verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    cherrypy.session['pubkey'] = pubkey_hex_str

def createSecretBox(secret_password):
    password_bytes = bytes(secret_password.encode('utf-8'))

    salt = (password_bytes * 16)[0:16]

    symmetric_key = nacl.pwhash.argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE, password_bytes, salt, opslimit=nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE, memlimit=nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE, encoder=nacl.encoding.HexEncoder)

    return nacl.secret.SecretBox(symmetric_key, encoder=nacl.encoding.HexEncoder)

def dictToBytes(dictionary):
    return bytes(json.dumps(dictionary).encode('utf-8'))

def detectIPAddressAndConnectionLocation():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    IP_address = s.getsockname()[0]
    s.close()

    if (IP_address.startswith("10.103")):
        connection_location = 0
    else:
        connection_location = 1
    return (IP_address, connection_location)


    
      
    












