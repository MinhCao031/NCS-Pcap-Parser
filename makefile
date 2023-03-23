LANGUAGE +=	-std=c99
OPTIMIZE +=	-O3
DEBUG +=	-g3
DEFINES +=	-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
WARNING +=	-Wall -Wextra 
WARNING +=  -Wno-unused-variable -Wno-unused-parameter -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-result -Wno-pointer-sign

# Come before C files
INCLUDED +=	`pkg-config --cflags --libs glib-2.0`

# C sources files & should be ordered from independent to dependent
CSOURCES +=	lib/dissection.c lib/parsers.c lib/linked_list.c lib/hash_table.c lib/handler.c 

# Come after C files & should be ordered from independent to dependent
LINKLIBS +=	-lpcap -lm

# Should be the last argument
SOURCE = main
SOURCE_CODE += $(SOURCE).c
OUTPFILE +=  $(SOURCE)

run: com clean
	./$(OUTPFILE)

dbg: com clean
	gdb $(OUTPFILE)

com: clean
	gcc $(DEBUG) $(WARNING) $(SOURCE_CODE) $(INCLUDED) $(CSOURCES) $(LINKLIBS) -o $(OUTPFILE)

clean:
	clear
	rm -rf *.o output*.txt* $(OUTPFILE)
