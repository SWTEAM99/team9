CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2 -Iinclude
LDFLAGS :=

APP     := crypto_app
TEST    := crypto_test

APP_SRC := app/app.c
TEST_SRC := test/test.c

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

APP_OBJS  := $(APP_SRC:.c=.o)
TEST_OBJS := $(TEST_SRC:.c=.o)
LIB_OBJS  := $(LIB_SRCS:.c=.o)

all: $(APP)

app: $(APP)

test: $(TEST)

$(APP): $(APP_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST): $(TEST_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(APP) $(TEST) $(APP_OBJS) $(TEST_OBJS) $(LIB_OBJS)

.PHONY: all app test clean
