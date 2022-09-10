all: bin/sparoid-server bin/sparoid

bin:
	mkdir bin

lib:
	shards install --production

bin/sparoid: src/client-cli.cr src/client.cr src/message.cr src/public_ip.cr | lib bin
	crystal build -o $@ --release --no-debug -Dgc_none $<

bin/sparoid-server: src/server-cli.cr src/server.cr src/message.cr src/config.cr | lib bin
	crystal build -o $@ --release --no-debug $<

clean:
	rm -rf bin

.PHONY: all clean
