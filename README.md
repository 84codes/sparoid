# SPAroid

Hide any server behind a deny all firewall, but open up the firewall for a single IP when a single correctly AES encrypted and HMAC authenticated UDP packet arrives. It allows you to hide eg. SSH for the wide internet, but still allow you to connect by just sending the UDP packet before the SSH connection attempt. Without VPN or jumphosts or other heavy weight solutions that are hard to scale.

Inspiration comes from [fwknop](http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html), but is implemented in [Crystal](https://www.crystal-lang.com).

The server listens on an UDP port, when it receives a message it tries to verify it (HMAC), decrypt it (AES-256-CBC), then verify the nounce (that it haven't been seen before, reply attack), that the timestamp is within 5s, and that the IP in the message matches the source IP.

If all checks passes the firewall is opened for the IP in the message. After 15s the port is closed again.

## Installation

Ubuntu:

```sh
wget -qO- https://packagecloud.io/cloudamqp/sparoid/gpgkey | sudo apt-key add -
echo "deb https://packagecloud.io/cloudamqp/sparoid/ubuntu/ $(lsb_release -cs) main" |\
  sudo tee /etc/apt/sources.list.d/sparoid.list
sudo apt-get update
sudo apt-get install -y sparoid
```

## Usage

Server:

```sh
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j DROP # reject new connections to 22 by default
bin/sparoid-server -k $key -H $hmac_key \
  --open-cmd "iptables -I INPUT -p tcp --dport 22 -s %s -j ACCEPT" \
  --close-cmd "iptables -D INPUT -p tcp --dport 22 -s %s -j ACCEPT"
```

Or with a config:

```sh
iptables -A INPUT -p tcp --dport 22 -j DROP # block connections to port 22
cat > config.ini << EOF
bind = 0.0.0.0
port = 8484
key = $key
hmac-key = $hmac_key
open-cmd = iptables -I INPUT -p tcp --dport 22 -s %s -j ACCEPT
close-cmd = iptables -D INPUT -p tcp --dport 22 -s %s -j ACCEPT
EOF
bin/sparoid-server --config config.ini
```

Client:

```sh
bin/sparoid keygen > ~/.sparoid.ini # will output a key and a hmac_key that will be used below

bin/sparoid send hidden.example.co
ssh hidden.example.co
```
