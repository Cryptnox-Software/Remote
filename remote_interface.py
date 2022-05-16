import socket
import threading
import pickle
from smartcard.System import readers
import sys
from pathlib import Path
import web3

from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC
import ast
import json
try:
    from . import config
except:
    import config

from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets


HEADER = 64
PORT = 5051
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'
SERVER = socket.gethostbyname(socket.gethostname() + ".local")
ADDR = (SERVER, PORT)
curve = registry.get_curve('secp256r1')

def send(conn,msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    conn.send(send_length)
    conn.send(message)

def send_data(connection,data):
    send(connection,'!Data')
    connection.send(data)

'''
Server-mode
'''

def exit_thread():
    exit_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exit_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    exit_client.connect((SERVER,5055))
    send(exit_client,'!EndThread')

def handle_client(conn,addr):
    connected_cards = []
    CARD_PORTS = [5055,5056,5057,5058]

    def relay_data(cryptnox,card):
        print(f'Receiving command from cryptnox, relaying it to card client')
        pickled_data = cryptnox.recv(1024)
        send_data(card,pickled_data)
        while True:
            msg_length = card.recv(64).decode('utf-8')
            if msg_length:
                msg_length = int(msg_length)
                msg = card.recv(msg_length).decode('utf-8')
                if msg == "!Data":
                    resp  = card.recv(1024)
                    send_data(cryptnox,resp)
                    break
                else:
                    print(f'Else:{msg}')
    print(f'New connection {addr} connected')
    try:
        print(f"Card is now connected.")
        card_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        card_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        card_server.bind((SERVER,5055))
        card_server.listen()
        print(f'Card awaiting connection from cryptnox')
        while True:
            connection,address = card_server.accept()
            try:
                while True:
                    msg_length = connection.recv(HEADER).decode(FORMAT)
                    if msg_length:
                        msg_length = int(msg_length)
                        msg = connection.recv(msg_length).decode(FORMAT)
                        print(f'Incoming to relay interface -> {msg}')
                        if msg == "!Data":
                            relay_data(connection,conn)
                        elif msg == "!EndThread":
                            raise KeyboardInterrupt()
                        else:
                            raise
            except KeyboardInterrupt as e:
                print(f'Breaking connection , exiting loop')
                connection.close()
                raise
            except Exception as e:
                print(f'Breaking connection to cryptnoxpro')
                connection.close()
    except (KeyboardInterrupt,Exception) as e:
        print(f'Ending card handler thread {e}')
        card_server.shutdown(socket.SHUT_RDWR)
        card_server.close()
                
def server_start():
    print(f'Starting server')
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(ADDR)
    server.listen()
    print(f'[Listening] Server is listening on {SERVER}')
    connections = []
    threads = []
    while True:
        try:
            conn, addr = server.accept()
            connections.append(conn)
            thread = threading.Thread(target=handle_client,args=(conn,addr))
            thread.start()
            threads.append(thread)
            print(f'Active connections: {threading.activeCount() - 1}')
        except (KeyboardInterrupt,Exception) as e:
            for each in connections:
                each.close()
            for each in threads:
                try:
                    exit_thread()
                except Exception as e:
                    print(f'No card_handle thread connection {e}')
                print('\nJoining sub-thread')
                each.join()
            print('Server is closing')
            server.shutdown(socket.SHUT_RDWR)
            server.close()
            break

'''
Client-mode
'''
def recv_data(conn,reader_connection):
    print(f'Receiving command from server')
    pickled_data = conn.recv(1024)
    command = pickle.loads(pickled_data)
    print(f'Transmitting APDU command to card')
    data, s1, s2 = reader_connection.transmit(command)
    response = [data,s1,s2]
    print(f'Responding back to server')
    pickled_response = pickle.dumps(response)
    send_data(conn,pickled_response)

def client_start():
    print(f'Starting client')
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server = '95.216.215.183'
    address = (server,PORT)
    client.connect(address)
    r = readers()
    reader_connection = r[0].createConnection()
    reader_connection.connect()
    while True:
        try:
            msg_length = client.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                msg = client.recv(msg_length).decode(FORMAT)
                if msg == "!Data":
                    print(f'Incoming-> {msg}')
                    recv_data(client,reader_connection)
        except (KeyboardInterrupt,Exception) as e:
            send(client,'!EndThread')
            client.close()
            print(f'Disconnecting {e}')
            break
    
'''
Tx-manager mode
'''

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

def handle_tx(conn,addr):
    while True:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            if msg == "!Data":
                pickled_data = conn.recv(1500)
                data = pickle.loads(pickled_data)
                with open('tx/private_key','rb') as file:
                    p_priv = file.read()
                decryptedMsg = decrypt_ECC(data['payload'], pickle.loads(p_priv))
                decoded = ast.literal_eval(decryptedMsg.decode('ascii'))

                pubdig = SHA256.new(json.dumps(decoded,sort_keys=True).encode('utf-8'))
                with open ("sk/public_key.pem", "r") as myfile:
                    public_key = ECC.import_key(myfile.read())

                verifier = DSS.new(public_key,'fips-186-3')
                try:
                    verified = verifier.verify(pubdig, data['signature'])
                    
                    if decoded['value']  > config.MAX_ETH_LIMIT:
                        raise ValueError({"message":f"Eth transfer amount {web3.Web3.fromWei(decoded['value'],'ether')} higher than limit {web3.Web3.fromWei(config.MAX_ETH_LIMIT,'ether')}."})

                    if decoded['to'] not in config.VALID_RECIPIENTS:
                        raise ValueError({"message":f"Account {decoded['to']} is not a valid recipient.\nPlease check address again or contact developer to add address to list on server."})

                    with open ("uk/private_key.pem", "r") as myfile:
                        private_key = ECC.import_key(myfile.read())

                    signer = DSS.new(private_key,'fips-186-3')
                    sig = signer.sign(pubdig)
                    enc_tx = str(decoded).encode('utf-8')
                    with open('tx/public_key','rb') as file:
                        p_pub = file.read()
                    encryptedMsg = encrypt_ECC(enc_tx, pickle.loads(p_pub))
                    data = {'payload':encryptedMsg,'signature':sig}
                except ValueError as ve:
                    print(f'Eth transfer amount higher than limit. {ve}')
                    data = {"error":ve.args[0]["message"]}
                except Exception as e:
                    print(f'Non-authentic server signature: {data}')
                    data = {'error':'Non-authentic server key signed'}
                finally:
                    print('========================================')
                    print('Blockchain:-\nUser:Signed\nServer:Signed')
                    print('========================================')
                    pickled_data = pickle.dumps(data)
                    send_data(conn,pickled_data)
                    break

def txmanager_start():
    print(f'Starting Tx-manager')
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(ADDR)
    server.listen()
    connections = []
    threads = []
    print(f'[Listening] Server is listening on {SERVER}')
    while True:
        try:
            conn, addr = server.accept()
            connections.append(conn)
            thread = threading.Thread(target=handle_tx,args=(conn,addr))
            thread.start()
            threads.append(thread)
            print(f'Active connections: {threading.activeCount() - 1}')
        except (KeyboardInterrupt,Exception) as e:
            for each in connections:
                each.close()
            for each in threads:
                each.join()
            print('Server is closing')
            server.shutdown(socket.SHUT_RDWR)
            server.close()
            break


if __name__ == '__main__':
    try:
        if len(sys.argv) > 1:
            mode = sys.argv[1]
            if mode.lower() == 'server':
                server_start()
            elif mode.lower() == 'client':
                client_start()
            elif mode.lower() == 'txmanager':
                txmanager_start()
            else:
                print(f'Invalid mode {mode}, please choose either "server" or "client"')
        else:
            print(f'Please specify mode to start with: [server,client,txmanager]\n e.g "python3 remote_interface.py server"')
    except Exception as e:
        print(f'Exiting program with exception: {e}')