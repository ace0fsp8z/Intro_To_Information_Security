# the compiler: gcc for C program, define as g++ for C++
CXX = g++
GCC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall

# the build target executable:
TASK2_TARGET = task2
TASK2_CXX = task2.cpp
SHARED_TARGET = shared
SHARED_TARGET_FILE = _des.so
OBJ = des.o
DES_FILE = des.c

all: $(TASK2_TARGET) $(SHARED_TARGET)

$(TASK2_TARGET):
	$(CXX) $(CFLAGS) -o $(TASK2_TARGET) $(TASK2_CXX) $(DES_FILE)

$(SHARED_TARGET):
	$(GCC) -fPIC -c $(DES_FILE) -o $(OBJ)
	$(GCC) -shared -o $(SHARED_TARGET_FILE) $(OBJ)
	$(RM) $(OBJ)

clean:
	$(RM) $(TASK2_TARGET) $(SHARED_TARGET_FILE)
