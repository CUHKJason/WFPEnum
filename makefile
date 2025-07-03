BOF_Function := WFPEnum
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

CC_X64 := x86_64-w64-mingw32-gcc


CFLAGS  := -Os -fno-asynchronous-unwind-tables
CFLAGS  += -fno-exceptions -fPIC 
CFLAGS  += -DPERSISTENT

#CFLAGS  := $(CFLAGS) -Os -fno-asynchronous-unwind-tables -fno-exceptions -fPIC 
LFLAGS := $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup
LDFLAGS := --no-seh --enable-stdcall-fixup -r -S

default:
	$(CC_X64) -c $(BOF_Function).c -DBOF -lfwpuclnt -o $(BOF_Function).x64.o

clean:
	rm $(BOF_Function).o