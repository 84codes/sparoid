all: bin/sparoid-server bin/sparoid

bin:
	mkdir bin

lib:
	shards install --production

bin/sparoid: | lib bin
	crystal build -o $@ --release --no-debug -Dgc_none src/client-cli.cr

bin/sparoid-server: | lib bin
	crystal build -o $@ --release --no-debug src/server-cli.cr

clean:
	rm -rf bin

.PHONY: all clean
