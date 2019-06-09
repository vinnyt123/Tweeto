import sqlite3
from sqlite3 import Error
import ast
from datetime import datetime


databasePath = "database.db"

class Database(object): 

    def __init__(self):
        self.createTables()

    def openConnection(self):
        try:
            return sqlite3.connect(databasePath)
        except Error as e:
            print("database connection error")
            return None

    def createTables(self):
        connection = self.openConnection()
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS BROADCASTS(loginserver_record text, message text, sender_created_at text, signature text)")
        cursor.execute("CREATE TABLE IF NOT EXISTS USERS(username text PRIMARY KEY, connection_address text, connection_location integer, incoming_pubkey text, connection_updated_at text, status text)")
        cursor.execute("CREATE TABLE IF NOT EXISTS MESSAGES(target_username text, sender_username text, sender_created_at text, encrypted_message text, signature text, target_pubkey text, loginserver_record text)")
        connection.commit()
        connection.close()

    def insertBroadcast(self, broadcastTuple):
        connection = self.openConnection()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO BROADCASTS VALUES(?,?,?,?)", broadcastTuple)
        connection.commit()
        connection.close()

    def insertMessage(self, messageTuple):
        connection = self.openConnection()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO MESSAGES VALUES(?,?,?,?,?,?,?)", messageTuple)
        connection.commit()
        connection.close()

    def getAllBroadcasts(self):
        connection = self.openConnection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM BROADCASTS b ORDER BY b.sender_created_at DESC")
        rows = cursor.fetchall()
        for i, row in enumerate(rows):
            broadcastDict = {}

            loginserver_record_list = row[0].split(',')
            broadcastDict['username'] = loginserver_record_list[0]
            broadcastDict['pubkey'] = loginserver_record_list[1]
            broadcastDict['server_time'] = loginserver_record_list[2]
            broadcastDict['signature'] = loginserver_record_list[3]

            broadcastDict['message'] = row[1]
            sender_created_at = float(row[2])
            formatted_sender_created_at = datetime.fromtimestamp(sender_created_at).strftime('%Y-%m-%d %H:%M:%S')
            broadcastDict['sender_created_at'] = formatted_sender_created_at
            broadcastDict['message_signature'] = row[3]
            rows[i] = broadcastDict

        return rows

    def getAllUsers(self):
        connection = self.openConnection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM USERS")
        return cursor.fetchall()

    def getMessageHistory(self, target_username, my_username, pubkey):
        connection = self.openConnection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM MESSAGES m WHERE ((m.target_username = ? AND m.sender_username = ?) OR (m.sender_username = ? AND m.target_username = ?)) AND m.target_pubkey = ?", (target_username, my_username, target_username, my_username, pubkey))
        rows = cursor.fetchall()

        for i, row in enumerate(rows):
            messageDict = {}

            messageDict['message'] = row[3]
            messageDict['sender_username'] = row[1]
            messageDict['target_username'] = row[0]
            sender_created_at = float(row[2])
            formatted_sender_created_at = datetime.fromtimestamp(sender_created_at).strftime('%Y-%m-%d %H:%M:%S')
            messageDict['sender_created_at'] = formatted_sender_created_at
            messageDict['target_pubkey'] = row[5]
            
            rows[i] = messageDict

        return rows
            


            





    

    

    
    
    
    