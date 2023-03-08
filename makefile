CFLAGS += -lpcap -Wall -Wextra -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings -Wstrict-prototypes -Wold-style-definition \
          -Wredundant-decls -Wnested-externs -Wmissing-include-dirs

LINKLIB += `pkg-config --cflags --libs glib-2.0`

run: com clean
	./main.o

com: clean
	gcc -O3 -o main.o main.c lib/dissection.c lib/hash_table.c lib/parsers.c lib/linked_list.c lib/handler.c $(CFLAGS)

clean:
	clear
	rm -rf *.o output*.txt
	