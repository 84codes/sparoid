# SPAroid

Hide any server behind a deny all firewall, but open up the firewall for a single IP when a single correctly AES encrypted and HMAC authenticated UDP packet arrives. It allows you to hide eg. SSH for the wide internet, but still allow you to connect by just sending the UDP packet before the SSH connection attempt. Without VPN or jumphosts or other heavy weight solutions that are hard to scale.

Inspiration comes from [fwknop](http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html), but is implemented in [Crystal](https://www.crystal-lang.com).

The server listens on an UDP port, when it receives a message it tries to verify it (HMAC), decrypt it (AES-256-CBC), then verify the nounce (that it haven't been seen before, reply attack), that the timestamp is within 5s. The IP that the packet arrives from and the IP that's in the packet (and the FW will be opened for), doesn't have to match, so a third party server can open the FW for another client.

If all checks passes the firewall is opened for the IP in the message. After 15s the port is closed again.

Direct nftables integration is also available, set the `nftables-cmd` and sparoid will interact with it directly without having to spawn a new process, which saves on resources.

## Installation

Ubuntu:

```sh
curl -fsSL https://packagecloud.io/cloudamqp/sparoid/gpgkey | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sparoid.gpg >/dev/null
# or with apt-key on older systems
# wget -qO- https://packagecloud.io/cloudamqp/sparoid/gpgkey | sudo apt-key add -
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
bind = ::
port = 8484
key = $SPAROID_KEY
hmac-key = $SPAROID_HMAC_KEY
nftables-cmd = add element inet filter sparoid { %s }
nftablesv6-cmd = add element inet filter sparoid6 { %s }
EOF

cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain prerouting {
    type filter hook prerouting priority -300
    udp dport 8484 meter rate-limit-sparoid { ip saddr limit rate over 1/second burst 8 packets } counter drop
    udp dport 8484 meter rate-limit-sparoid6 { ip6 saddr limit rate over 1/second burst 8 packets } counter drop
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
    ip6 saddr @sparoid6 tcp dport ssh accept
  }

  set sparoid {
    type ipv4_addr
    flags timeout
    timeout 5s
  }

  set sparoid6 {
    type ipv6_addr
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

#### Different keys for different services

Each `[section]` in the config file is a profile with its own keys and its own command, so that one sparoid server can open up for different services depending on which key the packet was sent with. The settings at the top of the file, before any section, are the default profile. A client that only has the `postgres` keys below can open port 5432, but not SSH.

```ini
bind = ::
port = 8484
key = $SPAROID_KEY
hmac-key = $SPAROID_HMAC_KEY
nftables-cmd = add element inet filter sparoid { %s }
nftablesv6-cmd = add element inet filter sparoid6 { %s }

[postgres]
key = $SPAROID_PG_KEY
hmac-key = $SPAROID_PG_HMAC_KEY
nftables-cmd = add element inet filter sparoid_pg { %s }
nftablesv6-cmd = add element inet filter sparoid_pg6 { %s }
```

With a matching set and rule per service in `nftables.conf`:

```
ip saddr @sparoid tcp dport ssh accept
ip6 saddr @sparoid6 tcp dport ssh accept
ip saddr @sparoid_pg tcp dport 5432 accept
ip6 saddr @sparoid_pg6 tcp dport 5432 accept
```

The profile is selected by the HMAC key, so every HMAC key has to be unique, and a profile must have a `key`, a `hmac-key` and a command. `bind` and `port` can only be set at the top of the file, and `default` can't be used as a section name since it's what the top of the file is called in log messages. Several profiles can use the same command, which is how you give two sets of keys access to the same service, or rotate keys. Nothing changes for the client, it just uses the keys of the service it should reach (`sparoid send --config ~/.sparoid-pg.ini`, or `SPAROID_KEY`/`SPAROID_HMAC_KEY`).

With iptables:

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

#### Changing the config file

Verify the config file before it's used, it exits with a non-zero status and prints the error if the file is invalid:

```sh
sparoid-server --config /etc/sparoid.ini --check
```

The server reloads the config file on `SIGHUP`, there's no need to restart it. If the file is invalid the error is logged and the server keeps running with the config it had, so a mistake in the file doesn't lock you out. `systemctl reload` runs the check first and fails if the file is invalid:

```sh
systemctl reload sparoid-server.service
```

`bind` and `port` can't be changed by a reload, that requires a restart.

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
