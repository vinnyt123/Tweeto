import os

import cherrypy

import clientServer
import myAPI

# The address we listen for connections on
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 10014

def runMainApp():
    #set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.getcwd(),
            'tools.encode.on': True, 
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout': 60 * 10, #timeout is in minutes, * 60 to get hours

            # The default session backend is in RAM. Other options are 'file',
            # 'postgres', 'memcached'. For example, uncomment:
            # 'tools.sessions.storage_type': 'file',
            # 'tools.sessions.storage_path': '/tmp/mysessions',
        },

        #configuration for the static assets directory
        '/static': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        },
        
        #once a favicon is set up, the following code could be used to select it for cherrypy
        #'/favicon.ico': {
        #    'tools.staticfile.on': True,
        #    'tools.staticfile.filename': os.getcwd() + '/static/favicon.ico',
        #},
    }

    cherrypy.site = {
        'base_path': os.getcwd()
    }

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(clientServer.MainApp(), "/", conf)
    cherrypy.tree.mount(myAPI.API(),"/api/", conf)

    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({'server.socket_host': LISTEN_IP,
                            'server.socket_port': LISTEN_PORT,
                            'engine.autoreload.on': True,
                           })

    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)  

    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
if __name__ == '__main__':
    runMainApp()
