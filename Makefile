CC := gcc
EXEC := ips

SRCS := ips.c main.c
OBJS := ${SRCS:c=o}

FLAGS      := -ansi
EXEC_FLAGS :=

OPENSSL := true

ifeq ($(OPENSSL), true)
	FLAGS += -D_OPENSSL -I/usr/local/opt/openssl/include
endif

ifeq ($(OPENSSL), true)
	EXEC_FLAGS += -L/usr/local/opt/openssl/lib -lssl -lcrypto
endif

all: $(EXEC)

%.o: %.c
	$(CC) -O -c $< -o $@ $(FLAGS)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(FLAGS) $(EXEC_FLAGS)

clean:
	rm -f $(EXEC) $(OBJS)
