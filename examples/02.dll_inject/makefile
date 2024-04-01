all:
	x86_64-w64-mingw32-gcc main.c -o target.exe
	x86_64-w64-mingw32-g++ -O3 -static -std=c++2a -I../.. -shared payload.cpp -o payload.dll
