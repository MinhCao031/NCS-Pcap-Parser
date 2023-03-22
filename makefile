LANGUAGE +=	-std=c99
OPTIMIZE +=	-O3
DEBUGGER +=	-g3
DEFINES +=	-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
WARNING +=	-Wall -Wextra -Wformat=2 -Wno-unused-parameter -Wshadow		\
        	-Wwrite-strings -Wstrict-prototypes -Wold-style-definition	\
        	-Wredundant-decls -Wnested-externs -Wmissing-include-dirs

# Come before C files
INCLUDED +=	`pkg-config --cflags --libs glib-2.0`

# C sources files & should be ordered from independent to dependent
CSOURCES +=	lib/dissection.c lib/parsers.c lib/linked_list.c lib/hash_table.c lib/handler.c main.c

# Come after C files & should be ordered from independent to dependent
LINKLIBS +=	-lpcap -lm

# Should be the last argument
OUTPFILE +=  main.o

run: com clean
	./$(OUTPFILE)

dbg: com clean
	gdb $(OUTPFILE)

com: clean
	gcc $(OPTIMIZE) $(WARNING) $(INCLUDED) $(CSOURCES) $(LINKLIBS) -o $(OUTPFILE)

clean:
	clear
	rm -rf *.o output*.txt*
