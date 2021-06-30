'''
This module defines the behaviour of server in your Chat Application
'''


import sys
import getopt
import socket
import util


class Server:
    '''
    This is the main Server Class. You will to write Server code inside this class.
    '''
    MAX_NUM_CLIENTS = 10
    
    def __init__(self, dest, port, window):
        self.server_addr = dest


        
        self.server_port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(None)
        self.sock.bind((self.server_addr, self.server_port))
        self.window = window
        self.list = {}

    
            
    def start(self):
        '''
        Main loop.
        continue receiving messages from Clients and processing it
        '''
        while True:
            message, addr = self.sock.recvfrom(4096)

            original_message = message
            # decoding and parsing message
            message = message.decode("utf-8")
            _,_,message,_ = util.parse_packet(message)

            typeOfMessage = util.message_type(message) # finding out type of message (join, send_message, etc.)

            if(typeOfMessage=="join"):  # if the message is a join request
                util.handle_join(self,message,addr)

            elif (typeOfMessage=="send_message"): # if the message is a send_message
                util.handle_send_message(self,message,addr)

            elif (typeOfMessage=="request_users_list"):
                util.handle_users_list(self,message,addr)

            elif typeOfMessage=="disconnect":
                util.handle_disconnect(self,message,addr)

            elif typeOfMessage=="file":
                util.handle_file(self,message,original_message,addr)

            elif(typeOfMessage=="quit"):
                break

            else:
                util.handle_unknown_message(self,message,addr)
        
        print("\nEnding Program")
        #handle_client(client_soc,addr)

        #raise NotImplementedError
    

# Do not change this part of code

if __name__ == "__main__":
    def helper():
        '''
        This function is just for the sake of our module completion
        '''
        print("Server")
        print("-p PORT | --port=PORT The server port, defaults to 15000")
        print("-a ADDRESS | --address=ADDRESS The server ip or hostname, defaults to localhost")
        print("-w WINDOW | --window=WINDOW The window size, default is 3")
        print("-h | --help Print this help")

    try:
        OPTS, ARGS = getopt.getopt(sys.argv[1:],
                                   "p:a:w", ["port=", "address=","window="])
    except getopt.GetoptError:
        helper()
        exit()

    PORT = 15000
    DEST = "localhost"
    WINDOW = 3

    for o, a in OPTS:
        if o in ("-p", "--port="):
            PORT = int(a)
        elif o in ("-a", "--address="):
            DEST = a
        elif o in ("-w", "--window="):
            WINDOW = a

    SERVER = Server(DEST, PORT,WINDOW)
    try:
        SERVER.start()
    except (KeyboardInterrupt, SystemExit):
        exit()
