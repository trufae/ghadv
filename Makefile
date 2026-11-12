PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
SRC = $(filter-out %_test.v,$(wildcard *.v))
BIN = gsadv

all: $(BIN)

$(BIN): $(SRC)
	v -o $(BIN) .

install: $(BIN)
	mkdir -p $(BINDIR)
	install -m 755 $(BIN) $(BINDIR)/$(BIN)

uninstall:
	rm -f $(BINDIR)/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all install uninstall clean
