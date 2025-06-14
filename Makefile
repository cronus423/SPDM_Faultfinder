CC			= gcc
OBJ_DIR 	= obj
FINDER_DIR 	= finder
HUNTER_DIR 	= hunter
SHARED_DIR	= shared
CJSON_DIR       = /usr/include/cjson
FINDER_OBJ	= faultfinder.o
HUNTER_OBJ  = faulthunter.o
#CFLAGS		= -I. -I$(FINDER_DIR) -I$(SHARED_DIR) 
LIBS 		= -lunicorn -lpthread -lcapstone -ljson-c -lm
CJSON_SRC   = /home/peiyao/program/cJSON/cJSON.c 
CFLAGS		= -g -I. -Wall -I. -I$(CJSON_DIR) -I$(SHARED_DIR)
#CFLAGS += -O2
CFLAGS += $(shell pkg-config --cflags json-c)
CFLAGS += -DCAPSTONE_AARCH64_COMPAT_HEADER
CFLAGS += -DCAPSTONE_SYSTEMZ_COMPAT_HEADER

LDFLAGS += $(shell pkg-config --libs json-c)

SOURCES		:=$(wildcard $(SHARED_DIR)/*.c $(SHARED_DIR)/consts/*.c)
OBJECTS		:=$(patsubst $(SHARED_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))
OBJECTS     	+= $(OBJ_DIR)/cJSON.o
all: faultfinder 

debug:	DEBUG= -DDEBUG
debug:	faultfinder

printinstructions: 	DEBUG=-DPRINTINSTRUCTIONS
printinstructions: 	faultfinder

urgh: 	DEBUG=-DPRINTINSTRUCTIONS -DDEBUG
urgh: 	faultfinder

$(OBJ_DIR)/%.o:	$(SHARED_DIR)/%.c
		$(info ************ SHARED $@ ************)
			mkdir -p $(dir $@)
			$(CC) -O0 -c $< -o $@  $(CFLAGS) $(DEBUG)

# cJSON Object File
$(OBJ_DIR)/cJSON.o: $(CJSON_SRC)
	$(info ************ COMPILING cJSON ************)
	mkdir -p $(OBJ_DIR)
	$(CC) -O0 -c $< -o $@ $(CFLAGS)
	
faultfinder: $(OBJECTS) $(FINDER_DIR)/faultfinder.c 
		$(info ************ FAULTFINDER ************)
			$(CC) -O0 -o $@  $^ $(CFLAGS) $(LIBS) $(DEBUG)


.PHONY: clean

clean:
	rm $(OBJ_DIR)/*.o $(OBJ_DIR)/consts/*.o  faultfinder

