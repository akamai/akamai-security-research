MAKE=make
CC=gcc
CFLAGS = -Wall -ggdb -O2 -D DEBUG=0 

all	: 
	make 	upx_dec	

upx_dec	: upx_dec.o
	$(CC) -O2 -o upx_dec upx_dec.o

clean	: 
	@echo "Cleaning up src files."
	@rm -f *.o upx_dec
