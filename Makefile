all: echoclient1 echoclient2 echoserver echoserver_fork

echoclient1: echoclient1.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoclient1 echoclient1.c eznet.c

echoclient2: echoclient2.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoclient2 echoclient2.c eznet.c

echoserver: echoserver.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoserver echoserver.c eznet.c

echoserver_fork: echoserver_fork.c eznet.c
	gcc -g -std=gnu11 -fsanitize=address -Wall -Werror -DSHOW_LOG_ERROR -oechoserver_fork echoserver_fork.c eznet.c

clean:
	rm echoclient echoserver
