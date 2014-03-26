PROGS=unco.dylib unco
DYLIB_OBJS=logger.o preload.o
CMD_OBJS=cmd.o

.c.o:
	$(CC) -Wall -c $<

all: $(PROGS)

unco.dylib: $(DYLIB_OBJS)
	$(CC) -Wall -ldl -dynamiclib $(DYLIB_OBJS) -o $@

unco: $(CMD_OBJS)
	$(CC) -Wall $(CMD_OBJS) -o $@

clean:
	rm -f $(PROGS)
