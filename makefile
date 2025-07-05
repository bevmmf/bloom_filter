bloom: bloom.c bloom.h test-bloom.c
	gcc -Wall -O2 -o $@ $^ -lcheck -lsubunit -lpthread -lm -lrt