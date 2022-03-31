CFLAGS = -lbsd
release: webserver
	-g -lbsd -std=gnu11 -Wall -Werror -DSHOW_LOG_ERROR

debug: webserver
	-g -std=gnu11 -Wall -Werror -DSHOW_LOG_ERROR -fsanitize=address -fno-omit-frame-pointer

all: echoclient1 echoclient2 webserver echoserver_fork

echoclient1: echoclient1.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoclient1 echoclient1.c eznet.c -lbsd

echoclient2: echoclient2.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoclient2 echoclient2.c eznet.c -lbsd

webserver: webserver.o eznet.o utils.o hash.o
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -owebserver webserver.o eznet.o utils.o hash.o -lbsd

echoserver_fork: echoserver_fork.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoserver_fork echoserver_fork.c eznet.c -lbsd

webserver.o: webserver.c utils.h
	gcc -c webserver.c -lbsd

utils.o: utils.c utils.h
	gcc -c utils.c -lbsd

hash.o: hash.c hash.h
	gcc -c hash.c -lbsd

eznet.o: eznet.c eznet.h
	gcc -c eznet.c -lbsd

clean:
	rm *.o webserver
