# ===============================
# Compiler (자동 선택)
# ===============================
# 기본값은 gcc
# macOS에서는 gcc가 clang alias로 동작
# 사용자가 원하면: make CC=clang
CC ?= gcc

# ===============================
# Compile Options
# ===============================
CFLAGS  = -Wall -Wextra -O2
TARGET  = crypto_app

# ===============================
# Source Files
# ===============================
SRC = app.c \
      AES_REF.c \
      AES_TABLE.c \
      T-table.c \
      crypto_api.c \
      error.c \
      hmac.c \
      modes.c \
      sha512.c \
      utils.c

OBJ = $(SRC:.c=.o)

# ===============================
# Build Rules
# ===============================
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
