import socket
import sys
import select
import threading

HOST: str = ''
PORT: int = 5000
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

inputs = [sys.stdin]
addresses = {}

lock_addresses = threading.Lock()

#list of active users
usernames = {}
lock_username = threading.Lock()

#ports for comunication
ports = {}
lock_ports = threading.Lock()

def init_server():
     # socket initialization (using the default internet address family and stream socket type) and binding
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))

    # awaits for a connection and stablishes a maximum of 5 pending connections
    sock.listen(1)

    # sets socket to non-blocking mode
    sock.setblocking(False)

    # includes socket in list of inputs that should be listened to
    inputs.append(sock)

    return sock
def accept_conection(sock):
    client_sock, address = sock.accept()
    print('Connected with: ', address)

    lock_addresses.acquire()
    addresses[client_sock] = address 
    lock_addresses.release()

    client_sock.setblocking(True)

    user = threading.Thread(target=interpret_request, args=(client_sock, address))
    user.start()

    return user
def close_conection(sock):
    global usernames

    lock_username.acquire()
    if sock in usernames.values():
        usernames = {key:val for key, val in usernames.items() if val is not sock}
    lock_username.release()

    lock_addresses.acquire()
    print('Disconnected with: ', addresses[sock])
    del addresses[sock]
    lock_addresses.release()

    sock.close()
    return

def respond(user, op = OK, content = 'null'):
    user.send(op.to_bytes(INT_SIZE, byteorder='little'))
    content_size = len(content)
    user.send(content_size.to_bytes(INT_SIZE, byteorder='little'))
    if content_size > 0:
        user.sendall(content.encode('utf-8'))
    return

def user_login(user, content = ''):

    content = content.split(',')
    username = content[0]
    port = int(content[1])

    lock_username.acquire()
    logged_in = (user in usernames.values())
    lock_username.release()
    if logged_in:
        respond(user, ERR, 'ERROR: Already logged in')

    lock_username.acquire()
    in_use = (username in usernames)
    lock_username.release()
    if in_use:
        respond(user, ERR, 'ERROR: Username ' + username + ' already in use, try another')
        return

    lock_username.acquire()
    usernames[username] = user
    lock_username.release()
    respond(user, OK, 'Logged in as ' + username)

    lock_ports.acquire()
    ports[user] = port
    lock_ports.release()
     
    lock_addresses.acquire()
    print(addresses[user], ' Logged in as ', username)
    lock_addresses.release()

    return
def user_logoff(user, content = ''):
    global usernames
    lock_username.acquire()
    logged_in = (user in usernames.values())
    lock_username.release()
    if not logged_in:
        respond(user, ERR, 'ERROR: user not found in active users list')
        return

    lock_username.acquire()
    usernames = {key:val for key, val in usernames.items() if val is not user}
    lock_username.release()

    lock_ports.acquire()
    del ports[user]
    lock_ports.release()
    respond(user, OK, 'Logged off with success')

    return
def send_list_to(user, content = ''):
    
    lock_username.acquire()
    userlist = {name for name in usernames if usernames[name] is not user}
    lock_username.release()

    if len(userlist) == 0:
        respond(user, LSTRE, "There are no active users right now")
        return
    respond(user, LSTRE, str(userlist))
    return
def send_addr_of(user, content = ''):

    lock_username.acquire()
    not_active = (content not in usernames)
    lock_username.release()
    if not_active:
        respond(user, ERR, 'ERROR: User ' + content + ' not found')
        return

    lock_username.acquire()
    is_self = (user is usernames[content])
    lock_username.release()
    if is_self:
        respond(user, ERR, 'ERROR: cannot connect with yourself')
        return

    lock_username.acquire()
    u = usernames[content]
    lock_username.release()

    lock_addresses.acquire()
    addr = addresses[u]
    lock_addresses.release()

    lock_ports.acquire()
    port = ports[u]
    lock_ports.release()

    if addr == '':
        respond(user, ERR, 'ERROR: user \''+content+'\' not found')
        return

    respond(user, ADDRE, addr[0] + ',' + str(port)) 

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
    
def interpret_request(client, addr):

    while True:
        #read header
        op = int.from_bytes( client.recv(INT_SIZE), byteorder='little' )

        # if client disconected
        if not op:
            close_conection(client)
            return

        content_size = int.from_bytes( client.recv(INT_SIZE), byteorder='little' ) 
        cont = recvall(client, content_size)

        if(op == LOGIN):
            user_login(client, cont)
        elif (op == LOGFF):
            user_logoff(client, cont)
        elif (op == LIST):
            send_list_to(client, cont)
        elif (op == ADDR):
            send_addr_of(client, cont)

def main():
    clients = []
    sock = init_server()
    print('Server Ready...\nType \'-t\' to terminate server execution')
    
    while True:
        r, w, err = select.select(inputs, [], [])
        for read in r:
            if read == sock: #new client connection
                client = accept_conection(sock)
                clients.append(client)
            elif read == sys.stdin: #command from terminal
                cmd = input()
                if cmd == '-t':
                    print('Waiting for all active clients to finish...')
                    for c in clients:
                        c.join()
                    sock.close()
                    sys.exit()

if __name__ == "__main__":
    main()