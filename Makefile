# 定义编译器和编译选项
CC = gcc
CFLAGS = 
LIB = -Llib -lgmssl

# 定义源文件和目标文件所在的目录
SRCDIR := src
OBJDIR := obj

# 定义要编译的源文件和目标文件
SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

# 定义输出文件名
TARGET := main

# 定义依赖关系和编译规则
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIB)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir $(OBJDIR)

# 定义清理规则
.PHONY: clean
clean:
	rm -rf $(OBJDIR) $(TARGET)
