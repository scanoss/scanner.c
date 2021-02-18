CC=gcc
# Enable all compiler warnings. 
CCFLAGS+= -fPIC -g -Wall -Werror -std=gnu99 -I./inc -I./external/inc -pthread

# Linker flags
LDFLAGS+=-lpthread -lcrypto -lssl -lcurl -lm
LIBFLAGS=-O -g -Wall -std=gnu99 -fPIC -c -lpthread

VERSION=`./scanner -h 2>&1  | head -n 1 | cut -d"-" -f2`

SOURCES_SCANNER=$(wildcard src/*.c) $(wildcard src/**/*.c)  $(wildcard external/*.c) $(wildcard external/**/*.c)
OBJECTS_SCANNER=$(SOURCES_SCANNER:.c=.o)

SOURCES_LIB=$(filter-out src/main.c, $(SOURCES_SCANNER))
OBJECTS_LIB=$(SOURCES_LIB:.c=.o)

TARGET_SCANNER=scanner
TARGET_LIB=lib
TARGET_NOINTEL=no_intel

LIB_NAME=libscanner.so
BIN_NAME=scanner
EXPORTED_HEADERS=$(wildcard inc/*.h)

$(TARGET_NOINTEL): CCFLAGS += -DCRC32_SOFTWARE_MODE

all: clean scanner deb

$(TARGET_SCANNER): $(OBJECTS_SCANNER)
	$(CC) -g -o $(BIN_NAME) $^ $(LDFLAGS) 

$(TARGET_LIB): $(OBJECTS_LIB)
	$(CC) -g -o $(LIB_NAME) $^ $(LDFLAGS) -shared -Wl,-soname,libscanner.so

$(TARGET_NOINTEL): $(OBJECTS_SCANNER)
	$(CC) -g -o $(BIN_NAME) $^ $(LDFLAGS) 


.PHONY: scanner lib no_intel

%.o: %.c
	$(CC) $(CCFLAGS) -o $@ -c $<

install:$(BIN_NAME)
	cp $(BIN_NAME) /usr/bin
install_lib:$(LIB_NAME)
	cp $(LIB_NAME) /usr/lib
	mkdir -p /usr/include/scanner && cp inc/scanner.h /usr/include/scanoss
clean_build:
	rm -f src/*.o src/**/*.o external/src/*.o external/src/**/*.o    

clean: clean_build
	rm -f $(BIN_NAME) $(LIB_NAME) *deb

distclean: clean

deb: $(TARGET_SCANNER) $(TARGET_LIB)
	@rm -rf dist/debian
	@mkdir -p dist/debian/DEBIAN
	@mkdir -p dist/debian/usr/include/scanoss
	@mkdir -p dist/debian/usr/lib
	@mkdir -p dist/debian/usr/bin
	cat packages/debian/control | sed "s/%VERSION%/$(VERSION)/" > dist/debian/DEBIAN/control
	@cp -vax $(TARGET_SCANNER) dist/debian/usr/bin
	@cp -vax $(EXPORTED_HEADERS) dist/debian/usr/include/scanoss
	@cp -vax $(LIB_NAME) dist/debian/usr/lib
	dpkg-deb --build dist/debian
	mv dist/debian.deb dist/scanoss-scanner-$(VERSION)-amd64.deb
	

