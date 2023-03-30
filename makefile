CC = clang
OPTIMIZE +=	-O3
DEBUG    +=	-g3
DEFINES +=	-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
WARNING +=	-Wall -Wextra 
WARNING += -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-pointer-sign

# Come before C files
INCLUDED +=	`pkg-config --cflags --libs glib-2.0`

# C sources files & should be ordered from independent to dependent
INCLUDED +=	lib/dissection.c lib/parsers.c lib/linked_list.c lib/hash_table.c lib/handler.c lib/ws/wsutil/str_util.c lib/ws/wsutil/wmem/wmem_strbuf.c ./lib/ws/wsutil/ws_assert.c ./lib/ws/wsutil/wmem/wmem_core.c ./lib/ws/wsutil/wslog.c ./lib/ws/wsutil/wmem/wmem_user_cb.c ./lib/ws/wsutil/wmem/wmem_allocator_simple.c ./lib/ws/wsutil/wmem/wmem_allocator_block_fast.c ./lib/ws/wsutil/wmem/wmem_allocator_strict.c ./lib/ws/wsutil/wmem/wmem_map.c ./lib/ws/wsutil/strtoi.c ./lib/ws/wsutil/to_str.c ./lib/ws/wsutil/wmem/wmem_list.c ./lib/ws/wsutil/wmem/wmem_strutl.c ./lib/ws/wsutil/inet_addr.c ./lib/ws/wsutil/wmem/wmem_allocator_block.c

# Come after C files & should be ordered from independent to dependent
LINKLIBS +=	-lpcap -lm

# Should be the last argument
SOURCE = test
SOURCE_CODE = $(SOURCE).c
OUTPFILE += $(SOURCE)

run: com clean
	./$(OUTPFILE)

db: com clean
	gdb $(OUTPFILE)

com: clean
	$(CC) $(SOURCE_CODE) $(DEBUG) $(WARNING) $(INCLUDED) $(LINKLIBS) -o $(OUTPFILE)

clean:
	clear
	rm -rf *.o output*.txt* $(OUTPFILE)
