'''
This file contains basic utility functions that you can use.
'''
import binascii

MAX_NUM_CLIENTS = 10
TIME_OUT = 0.5 # 500ms
NUM_OF_RETRANSMISSIONS = 3
CHUNK_SIZE = 5 # 1400 Bytes

def validate_checksum(message):
    '''
    Validates Checksum of a message and returns true/false
    '''
    try:
        msg, checksum = message.rsplit('|', 1)
        msg += '|'
        return generate_checksum(msg.encode()) == checksum
    except BaseException:
        return False


def generate_checksum(message):
    '''
    Returns Checksum of the given message
    '''
    return str(binascii.crc32(message) & 0xffffffff)


def make_packet(msg_type="data", seqno=0, msg=""):
    '''
    This will add the header to your message.
    The formats is `<message_type> <sequence_number> <body> <checksum>`
    msg_type can be data, ack, end, start
    seqno is a packet sequence number (integer)
    msg is the actual message string
    '''
    body = "%s|%d|%s|" % (msg_type, seqno, msg)
    checksum = generate_checksum(body.encode())
    packet = "%s%s" % (body, checksum)
    return packet


def parse_packet(message):
    '''
    This function will parse the packet in the same way it was made in the above function.
    '''
    pieces = message.split('|')
    msg_type, seqno = pieces[0:2]
    checksum = pieces[-1]
    data = '|'.join(pieces[2:-1])
    return msg_type, seqno, data, checksum


def make_message(msg_type, msg_format, message=None):
    '''
    This function can be used to format your message according
    to any one of the formats described in the documentation.
    msg_type defines type like join, disconnect etc.
    msg_format is either 1,2,3 or 4
    msg is remaining. 
    '''
    if msg_format == 2:
        msg_len = 0
        return "%s %d" % (msg_type, msg_len)
    if msg_format in [1, 3, 4]:
        msg_len = len(message)
        return "%s %d %s" % (msg_type, msg_len, message)
    return ""


#my functions

def message_type(msg):
    pieces = msg.split(' ')
    return pieces[0]

def get_username(msg):
    pieces=msg.split(' ')
    return pieces[2]

def get_username_from_address(self, addr):
    return list(self.list.keys())[list(self.list.values()).index(addr)]

def get_users_and_content(msg):
    pieces = msg.split(' ')
    content_length = int(pieces[1])

    
    users = []
    for x in range(int(pieces[3])):
        users.append(pieces[4+x])

    content=""
    for x in range(int(pieces[3])+4,len(pieces)):
        content+=pieces[x]
        if(x!=len(pieces)-1):
            content+=" "

    return users,content


def get_user_content_frwd(msg):
    pieces = msg.split(' ')
    content_length = int(pieces[1])

    users = []
    for x in range(int(pieces[2])):
        users.append(pieces[3+x])

    content=""
    for x in range(int(pieces[2])+3,len(pieces)):
        content+=pieces[x]
        if(x!=len(pieces)-1):
            content+=" "

    return users,content


def handle_join(self,message,addr):
    username = get_username(message)  # parse out username
    
    if len(self.list)==self.MAX_NUM_CLIENTS:
        message = make_message("err_server_full",2)
        message = make_packet(msg=message)
        message = message.encode("utf-8")

        self.sock.sendto(message,addr)

    elif username in self.list:
        reply="err_username_unavailable"
        reply = make_message(reply,2)
        reply = make_packet(msg=reply).encode("utf-8")

        self.sock.sendto(reply,addr)
        print("disconnected: username not available")
    
    else:
        self.list[username]=addr
        print("join:",username)


def handle_send_message(self,message,addr):
    # the following line of code parses out the list of users and message content

    users,content = get_users_and_content(message)

    username = get_username_from_address(self, addr)
    print("msg:",username)

    # now create a new message to be sent to recepients
    content = "1 " + username + " " + content

    new_message = make_message("forward_message",4,content)
    new_message = make_packet(msg=new_message)
    new_message = new_message.encode("utf-8")

    for x in users:
        if x not in self.list:
            print("msg:",username,"to non-existent user",x)
        else:
            self.sock.sendto(new_message,self.list[x])
    

def handle_users_list(self,message,addr):
    username = get_username_from_address(self,addr)
    print("request_users_list:",username)
    send_users_list(self,message,addr)

def send_users_list(self,message,addr):
    list_items = self.list.items()
    sorted_list_items = sorted(list_items)
    # studied this from www.kite.com/python/answers/how-to-sort-a-dictionary-by-key-in-python

    newcontent=""
    for x in range(0,len(sorted_list_items)):
        newcontent+=str(sorted_list_items[x][0])
        if(x!=len(sorted_list_items)-1):
            newcontent+=" "

    content = ""
    length = len(self.list)
    x=0
    for key in self.list:
        x=x+1
        content+=key
        if(x!=length):
            content+=" "
    
    message = make_message("response_users_list",3,newcontent)
    message = make_packet(msg=message)
    message = message.encode("utf-8")
    self.sock.sendto(message,addr)


def handle_unknown_message(self,message,addr):
    message = make_message("err_unknown_message",2)
    message = make_packet(msg=message)
    message = message.encode("utf-8")
    self.sock.sendto(message,addr)


def disconnectFromServer(self):
    content=self.name
    message = make_message("disconnect",1,content)
    message = make_packet(msg=message)
    message = message.encode("utf-8")

    self.sock.sendto(message,(self.server_addr,self.server_port))
    self.quit=True
    
def handle_disconnect(self,message,addr):
    pieces = message.split(" ") # example message = "disconnect 9 spiderman"
    username = pieces[2]
    del self.list[username]
    print("disconnected:",username)

def handle_file(self,message,original_message,addr):
    pieces = message.split(" ")
    username = get_username_from_address(self,addr)
    print("file:",username)

    users = []
    for x in range(3,3+int(pieces[2])):
        users.append(pieces[x])

    filecontent = "file 1 "
    filecontent += username
    filecontent += " "
    for x in range(3+int(pieces[2]),len(pieces)):
        filecontent+=pieces[x]
        if(x!=len(pieces)-1):
            filecontent+=" "

    message = make_message("forward_file",4,filecontent)
    message = make_packet(msg=message)
    message = message.encode("utf-8")

    for x in users:
        if x not in self.list:
            print("msg:",username,"to non-existent user",x)
        else:
            self.sock.sendto(message,self.list[x])

    # print(original_message.decode("utf-8"))


def client_join_server(self):
    joinmessage = make_message("join",1,self.name)
    joinmessage = make_packet(msg=joinmessage)
    self.sock.sendto(joinmessage.encode("utf-8"),(self.server_addr,self.server_port))

def client_send_msg(self, message):
    message = make_message("send_message", 4 ,message)
    message = make_packet(msg=message)
    self.sock.sendto(message.encode("utf-8"),(self.server_addr,self.server_port))

def client_request_users_list(self, message):
    message = make_message("request_users_list",2)
    message = make_packet(msg=message)
    self.sock.sendto(message.encode("utf-8"),(self.server_addr,self.server_port))


def client_send_file(self, message):
    tukray = message.split(" ")
    filename = tukray[len(tukray)-1]

    num_users = len(tukray)-1
    num_users = num_users-2

    content=""
    content+=str(num_users)
    content+=" "

    users = []
    for x in range(2,len(tukray)-1):
        users.append(tukray[x])
        content+=tukray[x]
        content+=" "
        
    f = open(filename,"rb")
    data = f.read(4096)
    data = data.decode()

    finalcontent = content+filename+" "+data

    message = make_message("file",4,finalcontent)
    message = make_packet(msg=message)
    message = message.encode("utf-8")

    self.sock.sendto(message,(self.server_addr,self.server_port))


def receive_file(self, message):
    pieces = message.split(" ")

    username = pieces[4]

    filename = pieces[4+int(pieces[3])]
    old_filename = filename
    filename = self.name + "_" + filename

    filecontent = ""
    
    for x in range(5+int(pieces[3]),len(pieces)):
        filecontent += pieces[x]
        if x!=len(pieces)-1:
            filecontent+=" "

    print("filecontent",filecontent)

    f = open(filename,"w")
    f.write(filecontent)
    f.close()

    print("file:",username+":",old_filename)
    # You need to recreate the original packet and send it to the client because you need to send the sender's username
    # to the client as well. The original packet that went from client to server had usernames of recepients, not of sender


def client_print_help():
    print("FORMATS")
    print("msg <number_of_users> <username1> <username2> ... <message>")
    print("Available Users: list")
    print("File Sharing: file <number_of_users> <username1> <username2> ... <file_name>")
    print("Quit: quit")


def client_print_response_users_list(message):
    pieces = message.split(" ")
    content=""
    for x in range(2,len(pieces)):
        content+=pieces[x]
        if(x!=len(pieces)-1):
            content+=" "
    print("list:",content)