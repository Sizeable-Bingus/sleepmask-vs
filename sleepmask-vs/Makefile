CPP_X64 = x86_64-w64-mingw32-g++
CFLAGS = -I../bof-vs/BOF-Template/base -I../bof-vs/BOF-Template/ -I./library -c -fno-stack-protector -fno-merge-all-constants -std=c++20 -fno-jump-tables -m64 -s
LD_x64 = x86_64-w64-mingw32-ld

all: draugr

draugr:
	nasm -f win64 library/stackspoofing.s -o ../x64/Release/spoofstub.o
	$(CPP_X64) $(CFLAGS) draugr-sleepmask.cpp -o ../x64/Release/draugr-sleepmask-template.o 
	$(LD_x64) -r ../x64/Release/spoofstub.o ../x64/Release/draugr-sleepmask-template.o -o ../x64/Release/draugr-sleepmask.x64.o
