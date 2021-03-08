# single-packet-authorization

[fwknop type of SPA service](http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html), implemented in crystal.

The server listens on UDP, when it receives a message it tries to verify it (HMAC), decrypt it (AES-256-CBC), then verify the nounce (that it haven't been seen before, reply attack), that the timestamp is within 10s, and that the IP in the message matches the source IP.

If all checks passes the firewall is opened for the IP in the message. After 15s the port is closed again.

## Installation

Ubuntu:

```bash
wget -qO- https://packagecloud.io/cloudamqp/spa-client/gpgkey | sudo apt-key add -
sudo cat > /etc/apt/sources.list.d/spa-client.list << EOF
deb https://packagecloud.io/cloudamqp/spa-client/ubuntu/ $(lsb_release -cs) main
EOF

sudo apt update
sudo apt install spa-client
```

## Usage

Server:

```sh
ufw deny ssh # reject new connections to 22 by default

bin/spa-server -k $key -H $hmac_key \
  --open-cmd "ufw allow from %s to any port 22 proto tcp" \
  --close-cmd "ufw delete allow from %s to any port 22 proto tcp"
```

Or with a config:

```sh
ufw deny ssh # reject new connections to 22 by default
cat > config.ini << EOF
key = $key
hmac-key = $hmac_key
open-cmd  = ufw allow from %s to any port 22 proto tcp
close-cmd = ufw delete allow from %s to any port 22 proto tcp
EOF
bin/spa-server --config config.ini
```

Client:

```sh
bin/spa-client keygen # will output a key and a hmac_key that will be used below

bin/spa-client send -k $key -H $hmac_key --host hidden.example.com
ssh hidden.example.com
```
