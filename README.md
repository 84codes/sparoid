# single-packet-authorization

[fwknop type of SPA service](http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html), implemented in crystal.

The server listens on UDP, when it receives a message it tries to verify it (HMAC), decrypt it (AES-256-CBC), then verify the nounce (that it haven't been seen before, reply attack), that the timestamp is within 10s, and that the IP in the message matches the source IP.

If all checks passes the firewall is opened for the IP in the message. After 15s the port is closed again.

## Installation

TODO: Write installation instructions here

## Usage

Server:

```sh
ufw deny ssh # reject new connections to 22 by default

bin/spa-server -k $key -H $hmac_key \
  --open-cmd "ufw allow from %s to any port 22 proto tcp" \
  --close-cmd "ufw delete allow from %s to any port 22 proto tcp"
```

Client:

```sh
bin/spa-client keygen # will output a key and a hmac_key that will be used below

bin/spa-client send -k $key -H $hmac_key --host hidden.example.com
ssh hidden.example.com
```

## Development

TODO: Write development instructions here

## Contributing

1. Fork it (<https://github.com/your-github-user/single-packet-authorization/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [your-name-here](https://github.com/your-github-user) - creator and maintainer
