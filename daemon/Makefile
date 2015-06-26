GCC=gcc
SOURCE_DIR=src
OBJS_DIR=objs
INCLUDE_DIR=inc
 
#WALL=-Wall
WALL=

OBJS_DAEMON=$(OBJS_DIR)/core.o $(OBJS_DIR)/udp.o $(OBJS_DIR)/trafficsqueezerd.o

HEADERS_DAEMON=$(INCLUDE_DIR)/core.h $(INCLUDE_DIR)/udp.h

all: trafficsqueezerd

clean-dirs:
	rm -rf $(OBJS_DIR)/*	

$(OBJS_DIR)/core.o:
	$(GCC) $(WALL) -c -o $(OBJS_DIR)/core.o $(SOURCE_DIR)/core.c

$(OBJS_DIR)/udp.o: $(OBJS_DIR)/core.o
	$(GCC) $(WALL) -c -o $(OBJS_DIR)/udp.o $(SOURCE_DIR)/udp.c

$(OBJS_DIR)/trafficsqueezerd.o: $(HEADERS_DAEMON) $(SOURCE_DIR)/trafficsqueezerd.c
	$(GCC) $(WALL) -c -o $(OBJS_DIR)/trafficsqueezerd.o $(SOURCE_DIR)/trafficsqueezerd.c

trafficsqueezerd: $(OBJS_DAEMON) $(OBJS_DIR)/trafficsqueezerd.o
	$(GCC) $(WALL) -o trafficsqueezerd $(OBJS_DAEMON)  -lpthread -lm

clean: clean-dirs
	rm -rf trafficsqueezerd
	rm -rf ../*~
	rm -rf ./*~
	rm -rf ./src/*~
	rm -rf ./inc/*~
	
install:
	make all
	rm -rf ../gui/trafficsqueezerd
	cp trafficsqueezerd ../gui/. 
