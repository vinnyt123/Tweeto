import cherrypy
import database
from database import Database

class API(object):

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_broadcast(self):

        input_json = cherrypy.request.json
        
        databaseObject = Database()

        newBroadcastTuple = (input_json['loginserver_record'], input_json['message'], input_json['sender_created_at'], input_json['signature'])

        databaseObject.insertBroadcast(newBroadcastTuple)

        print("YOU JUST GOT A LETTER!")
        print(input_json)

        response = {"response":"ok"}
    
        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_private_message(self):
        
        input_json = cherrypy.request.json

        databaseObject = Database()

        loginserver_record_list = input_json['loginserver_record'].split(',')
        sender_username = loginserver_record_list[0]

        newMessageTuple = (input_json['target_username'], sender_username, input_json['sender_created_at'], input_json['encrypted_message'], input_json['signature'], input_json['target_pubkey', input_json['loginserver_record']])

        databaseObject.insertMessage(newMessageTuple)
        print("YOU JUST GOT A PRIVATE MESSAGE!!")
        response = {"response":"ok"}

        return response
