

release: webserver
	-g -std=gnu11 -Wall -Werror -DSHOW_LOG_ERROR

debug: webserver
	-g -std=gnu11 -Wall -Werror -DSHOW_LOG_ERROR -fsanitize=address -fno-omit-frame-pointer

all: echoclient1 echoclient2 webserver echoserver_fork

echoclient1: echoclient1.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoclient1 echoclient1.c eznet.c

echoclient2: echoclient2.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoclient2 echoclient2.c eznet.c

webserver: webserver.o eznet.o utils.o
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -owebserver webserver.o eznet.o utils.o

echoserver_fork: echoserver_fork.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoserver_fork echoserver_fork.c eznet.c

webserver.o: webserver.c utils.h
	gcc -c webserver.c

utils.o: utils.c utils.h
	gcc -c utils.c

eznet.o: eznet.c eznet.h
	gcc -c eznet.c

clean:
	rm *.o webserver
