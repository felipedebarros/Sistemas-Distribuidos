import socket
import sys
import select
import threading
import random

HOST: str = 'localhost'
SERV_PORT: int = 5000
INT_SIZE: int = 4
HEADER_SIZE: int = INT_SIZE + INT_SIZE
#user operations
LOGIN: int = 1
LOGFF: int = 2
LIST: int = 3  
ADDR: int = 4
#hub operations
OK: int = 5
ERR: int = 6
LSTRE: int = 7
ADDRE: int = 8

#user-user operations
HELLO: int = 1
BYE: int = 2
MSG: int = 3

CLOSE: int = 0

listener_port = 0
name = ''
logged_in = False
inputs = [sys.stdin]

connections = {}
conn_lock = threading.Lock()

def init():
    global listener_port
    server = socket.socket()
    server.connect((HOST, SERV_PORT))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    while True:
        try:
            listener_port = random.randint(2000, 10000)
            listener.bind((HOST, listener_port))
            break
        except:
            continue

    listener.listen(1)

    listener.setblocking(False)

    inputs.append(listener)

    return server, listener
def terminate(server, listener):
    global logged_in
    while logged_in:
        logoff(server)

    server.close()
    listener.close()
    sys.exit()

    return

def recvall(sock, N):
    if(N <= 0):
        return ''

    chunks = []
    recieved = 0

    while recieved < N:
        chunk = sock.recv( min(N - recieved, 2048) )
        if not chunk:
            print('Content of message smaller than declared size')
        chunks.append(chunk)
        recieved += len(chunk)

    return str(b''.join(chunks), encoding='utf-8')

def send_msg(sock, op, content = 'null'):
    sock.send(op.to_bytes(INT_SIZE, byteorder='little'))
    content_size = len(content)
    sock.send(content_size.to_bytes(INT_SIZE, byteorder='little'))
    if content_size > 0:
        sock.sendall(content.encode('utf-8'))
    return
def interpret_response(sock):
    #read header
    op = int.from_bytes( sock.recv(4), byteorder='little' )

    if not op:
        return CLOSE, ''

    content_size = int.from_bytes( sock.recv(4), byteorder='little' )
    cont = recvall(sock, content_size)

    return op, cont

def server_login(server, username):
    if username == '':
        print('Username cannot be empty')
        return ERR

    send_msg(server, LOGIN, username + ',' + str(listener_port) )
    res, cont = interpret_response(server)

    if res != OK:
        print('Could not login')
        if res != ERR:
            print('Unexpected response from server')

    print(cont)
    return res
def server_logoff(server):
    global logged_in
    send_msg(server, LOGFF)
    res, cont = interpret_response(server)

    if res != OK:
        print('Could not login')
        if res != ERR:
            print('Unexpected response from server')

    print(cont)
    logged_in = False

    return res
def server_get_list(server):
    res = OK
    while(res != LSTRE):
        send_msg(server, LIST)
        res, cont = interpret_response(server)
        if res == ERR:
            print(cont)
            print("Trying again...")
    
    return cont
def server_get_user_addr(server, username):
    send_msg(server, ADDR, username)
    res, cont = interpret_response(server)

    if res != ADDRE:
        if res != ERR:
            print('Unexpected response from server')
            print(str(res) + ' ' + cont)
        else: 
            print(cont)
        return ''

    cont = cont.split(',')
    return (cont[0], int(cont[1]))

def user_connect_to(server, username):

    conn_lock.acquire()
    is_connected = username in connections
    conn_lock.release()
    if is_connected:
        print('Already connected to', username)
        return

    addr = server_get_user_addr(server, username)
    if addr == '':
        return

    user = socket.socket()
    user.connect(addr)

    conn_lock.acquire()
    connections[username] = user
    conn_lock.release()

    send_msg(user, HELLO, name + ',' + str(listener_port))

    print('Connected to', username)

    return
def user_disconnect_from(username):

    if username == '':
        print('[username] cannot be empty')

    conn_lock.acquire()
    not_connected = username not in connections
    conn_lock.release()
    if not_connected:
        print('You\'re not connected to', username)
        return 

    conn_lock.acquire()
    sock = connections[username]
    conn_lock.release()
    send_msg(sock, BYE)

    sock.close()
    conn_lock.acquire()
    del connections[username]
    conn_lock.release()

    print('Disconnected from', username)

    return
def user_disconnect_all():
    global connections

    conn_lock.acquire()
    conn = connections
    conn_lock.release()
    for user in conn:
        sock = conn[user]
        send_msg(sock, BYE)
        sock.close()

    conn_lock.acquire()
    connections = {}
    conn_lock.release()
    print('You\'re no longer connected to anyone')

    return
def user_send_msg_to(username, msg):
    conn_lock.acquire()
    not_connected = username not in connections
    conn_lock.release()
    if not_connected:
        print('You\'re not connected to:' + username)
        return 
    
    conn_lock.acquire()
    sock = connections[username]
    conn_lock.release()

    send_msg(sock, MSG, msg)
    print('['+username+'] You: '+msg)

    return
def user_send_msg_all(msg):
    
    conn_lock.acquire()
    conn = connections
    conn_lock.release()
    for user in conn:
        sock = conn[user]
        send_msg(sock, MSG, msg)

    print('[All] You: '+msg)

    return

def login(server):
    global name
    global logged_in
    if logged_in:
        print('Already logged in')
        return

    username = input('Choose a username: ')
    while (server_login(server, username) == ERR):
        username = input('Username invalid, try another: ')
    logged_in = True
    name = username
def logoff(server):
    global logged_in
    global name
    if not logged_in:
        print('You\'re not logged in')
        return

    print('Disconnecting from all users')
    user_disconnect_all()
    print('Logging off')
    res = server_logoff(server)

    if res == OK:
        logged_in = False
        name = ''
    return
def print_list(server):
    userlist = server_get_list(server)
    print('Users online: ', userlist)
def print_connections():
    conn_lock.acquire()
    users = connections.keys()
    conn_lock.release()
    print([ u for u in users ])
def help():
    print('List of commands')
    print('Type \'-u\' to recieve a updated version of the user list')
    print('Type \'-o\' to disconect from all chats and logoff')
    print('Type \'-i\' to login')
    print('Type \'-t\' to logoff and terminate execution')
    print('Type \'-c [username]\' to connect to another active user')
    print('Type \'-d [username]\' to disconnect from user')
    print('Type \'-p\' to see a list of all other users your\'re connected to')
    print('Type \'-w [username] [message]\' to whisper a message to a user')
    print('Type \'-b [message]\' to broadcast a message to al users you\'re connected to')
    print('Type \'-h\' for help')
    print('')

def parse_cmd(cmd, server):
    line = cmd.split(' ', 1)
    op = line[0]
    if   op == '-u':
        print_list(server)
    elif op == '-o':
        logoff(server)
    elif op == '-i':
        login(server)
    elif op == '-c':
        if(len(line) < 2):
            print('Error: not enough parameters')
            print('Type \'-c [username]\' to connect to another active user')
            return

        username = line[1]
        user_connect_to(server, username)
    elif op == '-d':
        if(len(line) < 2):
            print('Error: not enough parameters')
            print('Type \'-d [username]\' to disconnect from user')
            return

        username = line[1]
        user_disconnect_from(username)
    elif op == '-p':
        print_connections()
    elif op == '-w':
        line = cmd.split(' ', 2)
        if(len(line) < 3):
            print('Error: not enough parameters')
            print('Type \'-w [username] [message]\' to whisper a message to a user')
            return
        
        username = line[1]
        msg = line[2]
        user_send_msg_to(username, msg)
    elif op == '-b':
        if(len(line) < 2):
            print('Error: not enough parameters')
            print('Type \'-b [message]\' to broadcast a message to al users you\'re connected to')
            return

        msg = line[1]
        user_send_msg_all(msg)
    elif op == '-h':
        help()
    return 

def greetings(sock, addr):
    op, cont = interpret_response(sock)

    if op != HELLO:
        print('ERROR: Unexpected message recieved from a user')

    cont = cont.split(',')
    username = cont[0]
    port = int(cont[1])

    conn_lock.acquire()
    already_connected = username in connections
    conn_lock.release()
    if(already_connected):
        return username

    user = socket.socket()
    user.connect((addr[0], port))

    conn_lock.acquire()
    connections[username] = user
    conn_lock.release()

    send_msg(user, HELLO, name + ',' + str(listener_port))

    print(username + ' has connected')
    return username
def listen(sock, addr):
    username = greetings(sock, addr)
    while True:
        op, cont = interpret_response(sock)
        if op == CLOSE:
            break
        elif op == MSG:
            print('['+username+']: '+cont)
        elif op == BYE:
            conn_lock.acquire()
            conn = connections[username]
            conn.close()
            del connections[username]
            conn_lock.release()

            print(username + ' has disconnected')
            

    sock.close()
    return
def accept_connection(sock):
    user_sock, address = sock.accept()

    user_sock.setblocking(True)
    user = threading.Thread(target=listen, args=(user_sock, address))
    user.start()

    return user

def main():
    server, listener = init()

    login(server)

    print('Type \'-h\' to view all commands')

    print_list(server)

    while True:
        r, w, err = select.select(inputs, [], [])
        for read in r:
            if read == listener:
                accept_connection(listener)
            if read == sys.stdin:
                cmd = input()
                if cmd == '-t':
                    terminate(server, listener)
                else:
                    parse_cmd(cmd, server)

if __name__ == "__main__":
    main()