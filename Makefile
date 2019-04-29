LUA_DIR:=/usr
# LUA_LIBDIR:=$(LUA_DIR)/lib/lua/5.1
LUA_LIBDIR:=$(LUA_DIR)/include/lua5.1
LIBFLAG:=-shared -fpic -Wall --std=c99 -pedantic -Wno-pointer-sign -Werror
CFAGS:=-Wall --std=c99 -Werror -pedantic
DESTDIR:=$(shell pwd)

.PHONY: core.so

core.so: core.c
	$(CC) -o core.so $(LIBFLAG) $(CFLAGS) core.c -I$(LUA_LIBDIR) -llua5.1 -lssl -lcrypto
	$(CC) -o c_test $(CFLAGS) c_test.c -lssl -lcrypto

clean:
	$(RM) core.so

install:
	install -d -m0755        $(DESTDIR)/openssl
	install -m644 openssl.lua $(DESTDIR)/openssl
	install -m644 core.so    $(DESTDIR)/openssl
