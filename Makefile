PROGS=unco.dylib unco

all: $(PROGS)

unco.dylib: src/preload.c
	$(CC) -Wall -ldl -dynamiclib $< -o $@

unco: src/cmd.c
	$(CC) -Wall $< -o $@

clean:
	rm -f $(PROGS)
