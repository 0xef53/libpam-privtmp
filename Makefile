LIBSHARED = pam_privtmp.so
SOURCEFILE = pam_privtmp.c
PAM_LIB_DIR ?= /lib/security
RM = rm -f

CC = gcc
LDLIBS = -lpam

.PHONY: all install clean

all: $(LIBSHARED)

$(LIBSHARED): $(SOURCEFILE)
	$(CC) -shared -fPIC $(CFLAGS) $(LDLIBS) $< -o $@

install: $(LIBSHARED)
	install -m 0755 -d $(DESTDIR)$(PAM_LIB_DIR)
	install -m 0755 $(LIBSHARED) $(DESTDIR)$(PAM_LIB_DIR)

clean:
	$(RM) *.o *.so
