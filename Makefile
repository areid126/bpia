
CC = clang 
CFLAGS = -Wall -Wextra
CFILES = bpia.c
OFILES = bpia.o
PROGRAMS = bpia.exe

bpia: $(OFILES)
	$(CC) $(OFILES) -Llib -luser32 -o bpia.exe $(CFLAGS)

bpia.o: $(CFILES)
	$(CC) $(CFILES) -c -o $(OFILES) $(CFLAGS)

clean:
	-del *.o $(PROGRAMS)