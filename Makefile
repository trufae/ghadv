PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
SRC = ghadv.v
BIN = ghadv

all: $(BIN)

$(BIN): $(SRC)
	v -o $(BIN) $(SRC)

install: $(BIN)
	mkdir -p $(BINDIR)
	install -m 755 $(BIN) $(BINDIR)/$(BIN)

uninstall:
	rm -f $(BINDIR)/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all install uninstall clean
