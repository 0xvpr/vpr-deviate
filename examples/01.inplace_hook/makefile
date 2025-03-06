TARGET   = inplace.exe

CXX      = x86_64-w64-mingw32-g++
CXXFLAGS = -O3 -masm=intel -I../.. -std=c++2a -fPIC -fno-exceptions \
           -Wall -Wextra -Werror -Wshadow -Wpedantic -Wconversion


all: $(TARGET)
$(TARGET): main.cpp ../../vpr/deviate.hpp
	$(CXX) $(CXXFLAGS) main.cpp -o inplace.exe
