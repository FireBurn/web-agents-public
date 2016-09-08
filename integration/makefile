
SRC = ../source

CC = cc

CFLAGS = -D_GNU_SOURCE -std=gnu99 -O3 -pthread -I$(SRC)

LDFLAGS = -lpthread 

cache: test_cache.o share.o cache.o alloc.o rwlock.o
	$(CC) $(CFLAGS) -o cache test_cache.c cache.o share.o alloc.o rwlock.o $(LDFLAGS)

alloc: test_alloc.o alloc.o share.o
	$(CC) $(CFLAGS) -o alloc test_alloc.c share.o alloc.o $(LDFLAGS)

rwlock: test_rwlock.o rwlock.o
	$(CC) $(CFLAGS) -o rwlock test_rwlock.c rwlock.o $(LDFLAGS)

cache.o: $(SRC)/cache.h share.o alloc.o rwlock.o
	$(CC) -c $(CFLAGS) $(SRC)/cache.c

alloc.o: $(SRC)/alloc.h $(SRC)/alloc.c share.o 
	$(CC) -c $(CFLAGS) $(SRC)/alloc.c

rwlock.o: $(SRC)/rwlock.h $(SRC)/rwlock.c
	$(CC) -c $(CFLAGS) $(SRC)/rwlock.c

share.o: $(SRC)/share.h $(SRC)/share.c
	$(CC) -c $(CFLAGS) $(SRC)/share.c

all: cache alloc rwlock

clean:
	-rm -rf *.dSYM *.o cache rwlock alloc

