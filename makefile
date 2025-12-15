# ===== build settings =====
CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2 -Iinclude
LDFLAGS :=

TARGET  := crypto_app

# ===== sources =====
APP_SRC := app/app.c
LIB_SRCS := \
  src/AES_REF.c \
  src/AES_TABLE.c \
  src/T-table.c \
  src/crypto_api.c \
  src/error.c \
  src/hmac.c \
  src/modes.c \
  src/sha512.c \
  src/utils.c

SRCS := $(APP_SRC) $(LIB_SRCS)

# ===== objects (same folders) =====
OBJS := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# compile rule (keeps .o next to .c)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
