CC = gcc  # C compiler
CFLAGS = -fPIC -Wall -Wextra -Og -g  # C flags
LDFLAGS = -shared   # linking flags
RM = rm -f   # rm command
TARGET_LIB = libobfuscated.so  # target lib
TARGET_LIB_IDA = libobfuscated.so.i64  # target lib

SRCS = blog_manual_obfuscated.c blog_tigress_obfuscated.c blog_manual_ollvm.c # source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -s  -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${TARGET_LIB_IDA} ${OBJS} $(SRCS:.c=.d)
