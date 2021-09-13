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

### Server

With nftables:

```sh
cat > /etc/sparoid.ini << EOF
bind = 0.0.0.0
port = 8484
key = $SPAROID_KEY
hmac-key = $SPAROID_HMAC_KEY
open-cmd = nft add element inet filter sparoid { %s }
close-cmd =
EOF

cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain prerouting {
    type filter hook prerouting priority -300
    udp dport 8484 meter rate-limit-sparoid { ip saddr limit rate over 1/second burst 1 packets } counter drop
    udp dport 8484 notrack
  }

  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept

    ct state invalid counter drop
    ct state established,related accept

    udp dport 8484 accept
    ip saddr @jumphosts tcp dport ssh accept
    ip saddr @sparoid tcp dport ssh accept
  }

  set sparoid {
    type ipv4_addr
    flags timeout
    timeout 5s
  }

  set jumphosts {
    type ipv4_addr
    elements = { 10.10.10.10 }
  }
}

include "/etc/nftables/*.nft"
EOF

systemctl restart nftables.service sparoid.service
```

With iptables:

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

### Client

```sh
bin/sparoid keygen > ~/.sparoid.ini # will output a key and a hmac_key that will be used below

bin/sparoid send hidden.example.co
ssh hidden.example.co
```

The Sparoid client has integration with the OpenSSH client, just add the following to your `~/.ssh/config`: 

```
Host *
  ProxyCommand sparoid connect -h %h -P %p
  ProxyUseFdpass yes
``` 

It will then automatically send a UDP packet before connecting.
