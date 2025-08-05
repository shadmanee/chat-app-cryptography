# ─────────────────────────── server.py ────────────────────────────
import socket, threading
HOST, PORT = "0.0.0.0", 9999          # listen on every NIC
ENC = "utf-8"

sockets   = {}   # { ip : socket }
usernames = {}   # { ip : username }

def relay(conn, addr):
    ip = addr[0]

    # 1️⃣ first packet from the client is its username
    user = conn.recv(2048).decode(ENC)
    if not user:
        conn.close(); return
    sockets[ip]   = conn
    usernames[ip] = user
    print(f"[+] {user} ({ip}) connected")

    try:
        while True:
            data = conn.recv(2048).decode(ENC)
            if not data:
                break                      # client closed socket
            try:
                dest, payload = data.split("~", 1)   # DEST_IP~text
            except ValueError:
                conn.sendall("SERVER~Bad packet\n".encode(ENC))
                continue
            if dest in sockets:
                sockets[dest].sendall(f"{user}~{payload}".encode(ENC))
            else:
                conn.sendall(f"SERVER~{dest} not online\n".encode(ENC))
    finally:
        print(f"[-] {user} ({ip}) left")
        sockets.pop(ip, None)
        usernames.pop(ip, None)
        conn.close()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))                              # 0.0.0.0 binds every interface :contentReference[oaicite:1]{index=1}
    srv.listen()
    print(f"Relay server listening on {PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=relay, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()


# import socket, threading

# HOST          = "0.0.0.0"   # listen on all interfaces
# PORT          = 9999
# BACKLOG       = 20          # queued connections
# ENCODING      = "utf-8"

# # { client_ip : socket }
# clients       = {}
# # { client_ip : username } – purely for nicer labels
# usernames     = {}

# def handle_client(conn, addr):
#     ip = addr[0]

#     # 1️⃣ first packet = username
#     username = conn.recv(2048).decode(ENCODING)
#     if not username:
#         conn.close(); return

#     usernames[ip] = username
#     clients[ip]   = conn
#     print(f"[+] {username} ({ip}) connected")

#     try:
#         while True:
#             raw = conn.recv(2048).decode(ENCODING)
#             if not raw: break                           # disconnect

#             # expected: DEST_IP~message text
#             try:
#                 dest_ip, payload = raw.split("~", 1)
#             except ValueError:
#                 conn.sendall(f"SERVER~Malformed packet\n"
#                              .encode(ENCODING)); continue

#             if dest_ip in clients:                     # ✉️ forward
#                 msg = f"{username}~{payload}".encode(ENCODING)
#                 clients[dest_ip].sendall(msg)
#             else:                                      # ⛔ unknown peer
#                 conn.sendall(f"SERVER~{dest_ip} not online\n"
#                               .encode(ENCODING))
#     except (ConnectionResetError, OSError):
#         pass
#     finally:                                          # cleanup
#         print(f"[-] {ip} disconnected")
#         clients.pop(ip, None)
#         usernames.pop(ip, None)
#         conn.close()

# def main():
#     srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     srv.bind((HOST, PORT))
#     srv.listen(BACKLOG)
#     print(f"🔌  Server listening on {HOST}:{PORT}")

#     while True:
#         conn, addr = srv.accept()
#         threading.Thread(target=handle_client,
#                          args=(conn, addr), daemon=True).start()

# if __name__ == "__main__":
#     main()


# # # Import required modules
# # import socket
# # import threading

# # # HOST = '127.0.0.1'
# # HOST = '127.0.0.1'

# # #Use same IPV4 adress
# # print(HOST)
# # PORT = 9999 # You can use any port between 0 to 65535
# # LISTENER_LIMIT = 10
# # active_clients = [] # List of all currently connected users


# # def main():

# #     # Creating the socket class object
# #     # AF_INET: we are going to use IPv4 addresses
# #     # SOCK_STREAM: we are using TCP packets for communication
# #     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# #     # Creating a try catch block
# #     try:
# #         # Provide the server with an address in the form of
# #         # host IP and port
# #         server.bind((HOST, PORT))
# #         print(f"Running the server on {HOST} {PORT}")
# #     except:
# #         print(f"Unable to bind to host {HOST} and port {PORT}")

# #     # Set server limit
# #     server.listen(LISTENER_LIMIT)

# #     # This while loop will keep listening to client connections
# #     while 1:

# #         client, address = server.accept()
# #         print(f"Successfully connected to client {address[0]} {address[1]}")

# #         threading.Thread(target=client_handler, args=(client, )).start()

# # # Function to listen for upcoming messages from a client
# # def listen_for_messages(client, username):

# #     while 1:

# #         message = client.recv(2048).decode('utf-8')
# #         if message != '':
            
# #             final_msg = username + '~' + message
# #             send_messages_to_all(final_msg)

# #         else:
# #             print(f"The message send from client {username} is empty")


# # # Function to send message to a single client
# # def send_message_to_client(client, message):

# #     client.sendall(message.encode())

# # # Function to send any new message to all the clients that
# # # are currently connected to this server
# # def send_messages_to_all(message):
    
# #     for user in active_clients:

# #         send_message_to_client(user[1], message)

# # # Function to handle client
# # def client_handler(client):
    
# #     # Server will listen for client message that will
# #     # Contain the username
# #     while 1:

# #         username = client.recv(2048).decode('utf-8')
# #         if username != '':
# #             active_clients.append((username, client))
# #             prompt_message = "SERVER~" + f"{username} added to the chat"
# #             send_messages_to_all(prompt_message)
# #             break
# #         else:
# #             print("Client username is empty")

# #     threading.Thread(target=listen_for_messages, args=(client, username, )).start()
# # if __name__ == '__main__':
# #     main()