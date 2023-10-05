objs = beryl_cgi.o

dl_name = cgi.beryldl

CFLAGS += -std=c99 -Wall -Wextra -Wpedantic -O2 -fPIC

$dl_name: $(objs)
	$(CC) -shared $(objs) $(CFLAGS) -o$(dl_name) $(LINK_FLAGS)

install:
	cp $(dl_name) $(BERYL_SCRIPT_HOME)/libs/$(dl_name)

install-global:
	if [ -d /usr/local/berylscript ]; then cp $(dl_name) /usr/local/berylscript/libs/$(dl_name); fi

$(objs):

clean:
	rm ./*.o
	rm ./*.beryldl
