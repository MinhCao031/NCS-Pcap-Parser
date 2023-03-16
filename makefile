CFLAGS += -lpcap -Wall -Wextra -Wformat=2 -Wno-unused-parameter -Wno-unused-variable\
          -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wshadow\
          -Wredundant-decls -Wnested-externs -Wmissing-include-dirs

CFLAGS += `pkg-config --cflags --libs glib-2.0`

LIBS += lib/dissection.c lib/hash_table.c lib/parsers.c lib/linked_list.c lib/handler.c

run: com clean
	./main.o

com: clean
	gcc -g -o main.o main.c  $(LIBS) $(CFLAGS)

clean:
	clear
	rm -rf *.o output*.txt
	
