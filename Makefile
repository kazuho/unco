PROGS=unco.dylib unco
DYLIB_OBJS=log.o preload.o misc.o
CMD_OBJS=log.o cmd.o misc.o

.c.o:
	$(CC) -g -Wall -c $<

all: $(PROGS)

unco.dylib: $(DYLIB_OBJS)
	$(CC) -Wall -ldl -dynamiclib $(DYLIB_OBJS) -o $@

unco: $(CMD_OBJS)
	$(CC) -Wall $(CMD_OBJS) -o $@

clean:
	rm -f $(PROGS) $(DYLIB_OBJS) $(CMD_OBJS)
