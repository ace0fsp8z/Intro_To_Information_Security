# the compiler: gcc for C program, define as g++ for C++
CXX = g++

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall

# the build target executable:
TARGET = task1
SOURCE_CXX = task1.cpp
DES_FILE = des.cpp

all: $(TARGET)

$(TARGET):
	$(CXX) $(CFLAGS) -o $(TARGET) $(SOURCE_CXX) $(DES_FILE)

clean:
	$(RM) $(TARGET)
