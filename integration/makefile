
CC = clang -O3 -pthread

cache: test_cache.o share.o cache.o alloc.o rwlock.o
	$(CC) $(CFLAGS) -o cache test_cache.c cache.c share.o alloc.o rwlock.o -lpthread

alloc: test_alloc.o alloc.o share.o
	$(CC) -o alloc test_alloc.c share.o alloc.o -lpthread

rwlock: test_rwlock.o rwlock.o
	$(CC) -o rwlock test_rwlock.c rwlock.o -lpthread

cache.o: cache.h share.o alloc.o rwlock.o

alloc.o: alloc.h share.o

rwlock.o: rwlock.h

share.o: share.h

all: cache alloc rwlock

clean:
	-rm -f *.dSYM *.o cache rwlock alloc

