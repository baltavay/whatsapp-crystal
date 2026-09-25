.PHONY: build run format clean

build:
	mkdir -p bin
	crystal build --release -o bin/whatsapp-crystal src/cli.cr

run: build
	bin/whatsapp-crystal $(ARGS)

format:
	crystal tool format src

clean:
	rm -f bin/whatsapp-crystal
