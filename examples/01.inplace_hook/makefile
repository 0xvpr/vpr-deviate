TARGET   = inplace.exe

CXX      = x86_64-w64-mingw32-g++
CXXFLAGS = -O3 -I../.. -std=c++2a -fPIC \
           -Wall -Wextra -Werror -Wshadow -Wpedantic -Wconversion

all: $(TARGET)
$(TARGET): main.cpp ../../vpr/deviate.h
	$(CXX) $(CXXFLAGS) main.cpp -o inplace.exe
