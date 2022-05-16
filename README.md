# Card server

With options to run as either client or server, the script serves as an interface to enable remote communication between the card server and the CLI client.
This allows for the cryptnox CLI app to remotely recognize a card and issue commands as it were connected locally with a reader.

## Setup

1. Git clone version of cryptnoxpy with remote feature incorporated: https://github.com/christopherjude/cryptnoxpy
2. Git clone version of cryptnoxpro with remote feature incorporated: https://github.com/christopherjude/cryptnoxpro
3. cd into cloned directory and run `pip install .` to install
4. Git clone this repository

For ease of setup, an automated script 'remote_feature_setup' is available in this repo. Kindly run it with: `./remote_feature_setup`
 
_Note: It may prompt for gitlab credentials to clone this repo._

## Usage

### CLI client-side
1. Perform setup steps
2. Start the interface script as server:<br>
`python3 remote_interface.py server`


### Card server-side
3. Connect card reader to local machine
4. Insert card into card reader
5. Start the interface script as client:<br>
`python3 remote_interface.py client`

### CLI client-side
6. Invoke cryptnox CLI with port argument for remote mode:<br>
`cryptnox --port 5055`

## Process workflow

### Interface: As server
Starting the remote interface as 'server' creates a socket that listens on the machine's IP address on the defined port for incoming connections from the card server.

Once connected, a socket is created which listens on another dedicated port for incoming connections from Cryptnox CLI.

When Cryptnox CLI connects, the interface relays commands to/from the card server.

### Interface: As client
Starting the remote interface as 'client' creates a socket that connects to the defined remote IP.

Once connected, the card server awaits commands from the remote interface, transmitting any received APDU commands and sends the response back.



# Transaction & Signature Management

The script can also be run with the "txmanager" parameter, to serve as a remote transaction & signature manager for the cryptnox CLI.

## Setup

1. `pip install cryptnoxpy`
2. Git clone version of cryptnoxpro with remote tx check incorporated: https://github.com/christopherjude/cryptnoxpro
3. cd into cloned directory and change branch to rcsm with command: `git checkout rcsm`
3. Edit rcsm.py to use intended server IP address (line 22 in file cryptnoxpro/cryptnoxpro/command/rcsm.py) with command:<br>
`nano +22 cryptnoxpro/cryptnoxpro/command/rcsm.py`
4. `pip install .` to install
5. Git clone this repository on server
6. Edit config.py for allowed wallets & eth transaction limits

## Key Management

1. Create folders for key storage in local and remote with command: <br>
`mkdir -p ~/.cryptnoxkeys/sk ~/.cryptnoxkeys/tx ~/.cryptnoxkeys/uk`
2. Generate key-pair for sk (server keys) with command: <br>
`openssl ecparam -name secp256r1 -genkey -noout -out ~/.cryptnoxkeys/sk/private_key.pem`, then <br>
`openssl ec -in ~/.cryptnoxkeys/sk/private_key.pem -pubout -out ~/.cryptnoxkeys/sk/public_key.pem`<br>
and move public_key.pem to server under `~/.cryptnoxkeys/sk/<here>`
3. Generate 1st key-pair for tx (transaction keys) sending cli-to-server with command: <br>
`openssl ecparam -name secp256r1 -genkey -noout -out ~/.cryptnoxkeys/tx/private_key`, then <br>
`openssl ec -in ~/.cryptnoxkeys/tx/private_key -pubout -out ~/.cryptnoxkeys/tx/public_key`<br>
and move private_key to server under `~/.cryptnoxkeys/tx/<here>`
4. Generate 2nd key-pair for tx (transaction keys) sending server-to-cli with command: <br>
`openssl ecparam -name secp256r1 -genkey -noout -out ~/private_key`, then <br>
`openssl ec -in ~/private_key -pubout -out ~/public_key`, then <br>
`mv ~/private_key ~/.cryptnoxkeys/tx/.`<br>
and move public_key to server under `~/.cryptnoxkeys/tx/<here>`
5. Generate key-pair for uk (user keys) with command: <br>
`openssl ecparam -name secp256r1 -genkey -noout -out ~/.cryptnoxkeys/uk/private_key.pem`, then <br>
`openssl ec -in ~/.cryptnoxkeys/uk/private_key.pem -pubout -out ~/.cryptnoxkeys/uk/public_key.pem` <br>
move private_key to server under `~/.cryptnoxkeys/uk/<here>` <br>
and load public_key.pem onto card via cryptnox CLI with command: `user_key add pem`

## Usage

1. Peform setup & key-management steps
2. Start script on remote server in txmanager mode: `python3 remote_interface txmanager`
3. Perform transaction in cryptnox CLI: `eth send <address> <amount>`

## Process workflow

When performing a transaction with cryptnox CLI, the transaction (signed with server private key) will be sent to the txmanager server, where it will be checked against the server public key. 

Once validity has been confirmed, the deserialized transaction will be checked against defined restrictions/rules. If the transaction is valid, it will be sent back to the CLI signed with a user private key, whereas if not, it will send back an error, that is handled on the CLI side.

Returned back to the CLI, the transaction signature will be verified with the user public key from the card. If valid, the transaction will then be signed by cryptnox and broadcasted to the blockchain, whereas if invalid, the transaction is cancelled, displaying an error message.
