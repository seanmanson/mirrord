/*
 * Sean Manson - 42846413
 * COMP3301 Assignment 1 - Web Server
 * mirrord.c
 *
 * A basic web server, with simplified daemon functionality.
 * Uses libc, libevent and http-parser by Joyent.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <event.h>

#include "http_parser/http_parser.h"

#define CHUNK 1024
#define SMALLCHUNK 128

/* Structs */
struct conn { /* used to describe open TCP connections */
	char *			ip; /* client's ip as a readable string */

	/* events */
	struct event		rd_ev; /* read some data */
	struct event		wr_ev; /* writing some data */

	/* parsing of request */
	http_parser		parser; /* parser for http request */
	http_parser_settings	settings; /* settings for the above */
	int			mem_err; /* nonzero on malloc error */
	int			parse_err; /* nonzero on parsing error */

	/* internal data structures to help form response */
	char *			url; /* string with request url (not full) */
	int			url_len;
	int			retnum; /* response code number */
	struct evbuffer	*	head_buf; /* header of response (after gen) */
	int			head_fin_flag; /* finished writing head? */
	FILE *			content; /* page content for response */
	int			content_len;
};

/* Function Prototypes */
__dead void	usage(void);
char *		get_concat_string(char *, char *, int);
char *		get_retcode_for_retnum(int);
int		get_file_at_url_request(char *, FILE **, char *, int *);
char *		get_ip_for_cli_fd(int);
char *		get_curtime_rfc822(void);
struct conn *	new_connection_object(void);
int		conn_update_url(http_parser *, const char *, size_t);
int		conn_finish_parse(http_parser *);
void		conn_generate_header(struct conn *);
void		on_conn_accept(int, short, void *);
void		on_conn_read(int, short, void *);
void		on_conn_write(int, short, void *);
void		conn_log_request(struct conn *);
void		conn_close(struct conn *);
int		set_global_vars(FILE *, char *);
int		get_options(int, char **, int *, struct addrinfo **, FILE **);
int		new_server_socket(struct addrinfo *);

/* Global Variables - these are set in the set_global_vars func */
static char *	gbl_working_dir = NULL; /* The directory to serve files from */
static FILE *	gbl_log_file = NULL;


/*
 * Prints a usage statement for this program to stderr before exiting.
 */
__dead void
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-46d] [-a access.log] [-l address] "
	    "[-p port] directory\n", __progname);
	exit(1);
}

/*
 * Concatenates the two given strings into a new string, which is malloc'd.
 * Works up to len chars - len is needed to avoid compiler warnings.
 *
 * Returns NULL on malloc fail, or the new string otherwise. Must be freed at
 * some point.
 */
char *
get_concat_string(char *str1, char *str2, int len)
{
	char *res;

	/* we include terminator */
	res = malloc(len * sizeof(char));
	if (res == NULL)
		return NULL;
	strlcpy(res, str1, len);
	strlcat(res, str2, len);

	return res;
}

/*
 * Returns a string code for some HTTP response header number (a retnum).
 */
char *
get_retcode_for_retnum(int retnum)
{
	switch (retnum) {
	case 200:
		return "200 OK";
	case 400:
		return "400 Bad Request";
	case 403:
		return "403 Forbidden";
	case 404:
		return "404 Not Found";
	case 405:
		return "405 Method Not Allowed";
	default:
		return "500 Internal Server Error";
	}
}

/*
 * Returns a string human-readable ip address for a client socket fd at the
 * given fd. Returns NULL on failure. This string is malloc'd, and must be
 * freed later. The fd provided must be currently connected.
 */
char *
get_ip_for_cli_fd(int fd)
{
	struct sockaddr_storage info;
	int info_len = sizeof(info);
	char *ip = NULL;

	/* Get peer info about this fd (fails if not a socket/not connected)*/
	if (getpeername(fd, (struct sockaddr *)&info, &info_len) == -1)
		return NULL;
	
	switch (info.ss_family) {
	case AF_INET:
		ip = malloc(INET_ADDRSTRLEN * sizeof(char));
		inet_ntop(AF_INET, &((struct sockaddr_in *)&info)->sin_addr,
		    ip, INET_ADDRSTRLEN);
		break;

	case AF_INET6:
		ip = malloc(INET6_ADDRSTRLEN * sizeof(char));
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&info)->sin6_addr,
		    ip, INET6_ADDRSTRLEN);
		break;
	}

	return ip;
}

/*
 * Returns the current server time as a string, in GMT RFC822 format.
 * This string is malloc'd, so it must be freed later.
 * The string is limited to being SMALLCHUNK chars long.
 */
char *
get_curtime_rfc822(void)
{
	time_t tm_val;
	char *tm_format;
	struct tm *tm_info;

	/* obtain the current GMT time for this machine */
	time(&tm_val);
	tm_info = gmtime(&tm_val);

	/* Create string to store with */
	tm_format = malloc(SMALLCHUNK * sizeof(char));
	if (tm_format == NULL)
		return NULL;

	/* Format time within this string */
	strftime(tm_format, SMALLCHUNK, "%a, %d %b %Y %H:%M:%S GMT", tm_info);
	return tm_format;
}

/*
 * For some valid HTTP url request, this function tries to open the file
 * pointed at by this url, updating the value pointed to by f to a file
 * pointer for that file.
 * file_time is updated with SMALLCHUNK characters worth of the GMT time for
 * this file's modification date, in RFC822 format.
 * The value at file_len is updated to be an int for the size of the file.
 *
 * Returns the appropriate error number for a http request for this file:
 *  500 - malloc fail
 *  404 - not found/invalid file/not a file
 *  403 - not enough permissions
 *  200 - success
 */
int
get_file_at_url_request(char *url, FILE **f, char *file_time, int *file_len)
{
	char *fileloc;
	struct stat info;
	struct tm *file_tm_info;
	
	/* Ensure no invalid character sequences */
	if (url == NULL || strlen(url) == 0 || strstr(url, "../") != NULL)
		return 404;
	
	/* Get mallocs for full file location and file time */
	fileloc = get_concat_string(gbl_working_dir, url,
	    1 + strlen(gbl_working_dir) + strlen(url));
	if (fileloc == NULL)
		return 500;

	/* Read file, and ensure it is a standard file */	
	if (stat(fileloc, &info) != 0 || !S_ISREG(info.st_mode)) {
		free(fileloc);
		return 404;
	}

	/* Get time since modification, and format it */
	file_tm_info = gmtime(&(info.st_mtime));
	strftime(file_time, SMALLCHUNK, "%a, %d %b %Y %H:%M:%S GMT",
	    file_tm_info);

	/* Get length of file */
	*file_len = info.st_size;
	
	/* Try to open file at fileloc */
	if ((*f = fopen(fileloc, "r")) == NULL) {
		free(fileloc);
		switch (errno) {
		case EACCES:
			return 403;
		case ENOENT:
			return 404;
		default:
			return 500;
		}
	}

	/* Success! */
	free(fileloc);
	return 200;
}

/*
 * Creates a new connection struct object thingo, defined by struct conn at
 * the top of this file. These structs represent a current connection by
 * the client, and are used to know the current status of communication when
 * being tossed around from event to event.
 */
struct conn *
new_connection_object(void)
{
	struct conn *c;

	/* Set defaults for core memory structures */
	c = malloc(sizeof(*c));
	if (c == NULL) {
		return NULL;
	}
	if ((c->head_buf = evbuffer_new()) == NULL) {
		free(c);
		return NULL;
	}
	c->retnum = 444;
	c->head_fin_flag = c->parse_err = c->mem_err = 0;
	c->url_len = c->content_len = 0;
	c->ip = NULL;
	c->url = NULL;
	c->content = NULL;

	/* HTTP parser creation for this connection */
	http_parser_init(&c->parser, HTTP_REQUEST);
	http_parser_settings_init(&c->settings);
	(c->parser).data = (void *)c;
	(c->settings).on_url = conn_update_url;
	(c->settings).on_message_complete = conn_finish_parse;

	return c;
}

/*
 * Occurs when the http_parser gains some url chars. Because this can happen
 * multiple times, we simply add new chars to a buffer and wait until later
 * to deal with them.
 */
int
conn_update_url(http_parser *p, const char *at, size_t len)
{
	int i;
	struct conn *c = (struct conn *)p->data;

	/* add room for more bytes */
	c->url = realloc(c->url, (c->url_len + len + 1) * sizeof(char));
	if (c->url == NULL) {
		c->mem_err = 1; /* set memory error flag for later */
		return 0;
	}

	/* append these bytes */
	for (i = 0; i < len; i++)
		c->url[c->url_len + i] = at[i];
	c->url[c->url_len + len] = '\0';

	c->url_len += len;
	return 0;
}

/*
 * Occurs when we finish parsing a whole message in the http_parser.
 * We stop reading from the client (who cares if they send gibberish now?)
 * and start forming a response, ready to send when the write event comes.
 */
int
conn_finish_parse(http_parser *p)
{
	struct conn *c = (struct conn *)p->data;
	
	/* Finished parsing message; now ready to give a response */
	event_del(&c->rd_ev);
	conn_generate_header(c);
	event_add(&c->wr_ev, NULL);
	
	return 0;
}

/*
 * Using data gathered in the given connection struct and parser, put together
 * a header and prepare to give a response.
 *
 * This is a bit complex, as in some cases we need to know our body data in
 * order to generate the relevant headers.
 */
void
conn_generate_header(struct conn *c)
{
	char *time;
	char file_time[SMALLCHUNK];

	/* if we got here, then we read header correctly */
	c->retnum = 200;

	/* get formatted time */
	time = get_curtime_rfc822();

	/* set retcodes for unsupported methods and errors */
	if ((c->parser).method != HTTP_GET && (c->parser).method != HTTP_HEAD)
		c->retnum = 405;

	/* invalid message and server error overrides all */
	if (c->mem_err == 1)
		c->retnum = 500;
	if (c->parse_err == 1)
		c->retnum = 400;
	
	/* try to load file */
	if (c->retnum == 200 && c->url != NULL)
		c->retnum = get_file_at_url_request(c->url, &c->content,
		    file_time, &c->content_len);
	if (c->retnum == 200 && (c->parser).method == HTTP_HEAD) {
		fclose(c->content);
		c->content = NULL;
	}

	/* start putting together response headers */
	evbuffer_add_printf(c->head_buf, "HTTP/1.0 %s\r\nDate: %s\r\nServer: "
	    "mirrord/s4284641\r\nConnection: close\r\n",
	    get_retcode_for_retnum(c->retnum), time);
	if (c->retnum == 200)
		evbuffer_add_printf(c->head_buf, "Content-Length: %d\r\n"
		    "Last-Modified: %s\r\n", c->content_len, file_time);
	evbuffer_add_printf(c->head_buf, "\r\n");

	free(time);
}

/*
 * EVENT
 * Occurs when svr_fd is ready to accept a new connection.
 *
 * We try to accept the connection if we can, create a conn for it and then
 * start read events for the client socket.
 */
void
on_conn_accept(int svr_fd, short evtype, void *null)
{
	struct sockaddr_storage cli_sock;
	struct conn *c;
	int cli_fd;
	socklen_t cli_socklen = sizeof(cli_sock);
	int on = 1;

	/* try to accept the connection, and make it non-blocking */
	cli_fd = accept(svr_fd, (struct sockaddr *)&cli_sock, &cli_socklen);
	if (cli_fd == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			/* ignore this connection */
			return;
		default:
			err(1, "bad accept");
		}
	}
	if (ioctl(cli_fd, FIONBIO, &on) == -1)
		err(1, "ioctl(FIONBIO) for connection");

	/* create a new connection struct to handle this connection */
	if ((c = new_connection_object()) == NULL) {
		close(cli_fd);
		return;
	}

	/* set client ip for this connection obj */
	c->ip = get_ip_for_cli_fd(cli_fd);

	/* Set up event handling for comms on this connection */
	event_set(&c->rd_ev, cli_fd, EV_READ | EV_PERSIST, on_conn_read, c);
	event_set(&c->wr_ev, cli_fd, EV_WRITE, on_conn_write, c);	
	event_add(&c->rd_ev, NULL);
}

/*
 * EVENT
 * Occurs when the client socket is ready to be read from. This happens
 * continuously until we tell our conn struct to stop listening.
 *
 * We parse any bytes we get to the http_parser, which runs conn_finish_parse
 * once done. When that happens, we stop listening for read events. Groovy.
 *
 * On client exit, we close the connection entirely on read.
 * On invalid client data, we jump straght to conn_finish_parse.
 */
void
on_conn_read(int cli_fd, short evtype, void *conn)
{
	char readbuf[CHUNK];
	ssize_t num, parsed;
	struct conn *c = (struct conn *)conn;
	
	/* attempt to read as much as possible, parsing for each chunk */
	do {
		/* Attempt to read as much as possible */
		num = recv(cli_fd, readbuf, CHUNK, 0);
		if (num == -1) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				/* try again later */
				return;
			default:
				/* disconnected - tear down client */
				conn_close(c);
				return;
			}
		}

		/* Parse read bytes. On bad parse, set error flag and fin */
		parsed = http_parser_execute(&c->parser, &c->settings, readbuf,
		    num);
		if (parsed != num) {
			c->parse_err = 1;
			conn_finish_parse(&c->parser);
			return;
		}
	} while (num == CHUNK);
}

/*
 * EVENT
 * Occurs when the client socket is ready to be written to. This event is
 * added such that it only fires when we actually have data to send.
 *
 * Data to send comes in two forms:
 *  - evbuffer data for the header
 *  - FILE * data for the body
 * This function attempts to progress through writing the above, one CHUNK at
 * a time. When successful (or not successful, if client was not ready), we
 * return from this function and add this event to the end of the event queue
 * again. This allows multiple sets of writing events to co-exist and finish
 * simultaneously.
 *
 * This event only stops firing when either the client exits/socket closes
 * in some way, or if all data has been sent. In either case, it runs
 * conn_close and returns without adding itself again to the event queue.
 */
void
on_conn_write(int cli_fd, short evtype, void *conn)
{
	char write_buf[CHUNK];
	int num;
	struct conn *c = (struct conn *)conn;

	/* First, send all data in the header evbuffer */
	if (c->head_fin_flag == 0) {
		num = evbuffer_write(c->head_buf, cli_fd);
		if (num == -1) {  /* error writing on socket */
			switch (errno) {
			case EINTR:
			case EAGAIN: /* Can't write; try again later */
				event_add(&c->wr_ev, NULL);
				return;
			default: /* disconnected - tear down client */
				c->retnum = 444;
				conn_close(c);
				return;
			}
		} else if (num == 0) /* finished sending header; now body */
			c->head_fin_flag = 1;
		
		event_add(&c->wr_ev, NULL); /* repeat until finished */
		return;
	}

	/* Next, start to send file data, if we have any */
	if (c->content != NULL) {
		/* Read file into buffer */
		num = fread(write_buf, sizeof(char), CHUNK, c->content);
		if (num != CHUNK && feof(c->content) == 0) {
			conn_close(c);
			return;
		}

		/* Send file data, resetting stream pointer on failure */
		if ((send(cli_fd, write_buf, num, 0)) == -1) {
			switch (errno) {
			case EINTR:
			case EAGAIN: /* Can't write; try again later */
				fseek(c->content, -num, SEEK_CUR);
				event_add(&c->wr_ev, NULL);
				return;
			default: /* disconnected - tear down client */
				c->retnum = 444;
				conn_close(c);
				return;
			}
		}

		/* If we sent data, repeat this function */
		if (num > 0) {
			event_add(&c->wr_ev, NULL);
			return;
		}
	}

	/* Done writing response! Now close. */
	conn_close(c);
}

/*
 * Log a single request to the global log file representing the response we
 * gave to the given conn. Assumes log file exists. Requests are in the form:
 *    ip [rfc822time] "requestmethod url" requestnum bytes_sent
 */
void
conn_log_request(struct conn *c)
{
	char *time, *method;
	int data_bytes = c->content_len;

	/* Get time */
	time = get_curtime_rfc822();

	/* Get method */
	if ((c->parser).method == HTTP_GET)
		method = "GET";
	else if ((c->parser).method == HTTP_HEAD) {
		method = "HEAD";
		data_bytes = 0;
	} else
		method = "-";

	/* Print to file based on response code */
	if (c->retnum == 200)
		fprintf(gbl_log_file, "%s [%s] \"%s %s\" 200 %d\n", c->ip,
		    time, method, c->url, data_bytes);
	else if (c->retnum == 403 || c->retnum == 404)
		fprintf(gbl_log_file, "%s [%s] \"%s %s\" %d 0\n", c->ip,
		    time, method, c->url, c->retnum);	
	else
		fprintf(gbl_log_file, "%s [%s] \"- -\" %d 0\n", c->ip, time,
			c->retnum);
	fflush(gbl_log_file);

	/* done */
	free(time);
}

/*
 * Close the given connection, regardless of status. Records this connection
 * to the log file. Closes and frees all related memory structures, if they
 * exist. Removes related socket events entirely.
 */
void
conn_close(struct conn *c)
{
	/* Log request */
	if (gbl_log_file != NULL)
		conn_log_request(c);

	/* Close and free all connection data */
	if (c->content != NULL)
		fclose(c->content);
	event_del(&c->wr_ev);
	event_del(&c->rd_ev);
	close(EVENT_FD(&c->rd_ev));
	evbuffer_free(c->head_buf);
	free(c->url);
	free(c->ip);
	free(c);
}

/*
 * Sets the global log file and directory location to the given values.
 * Checks the directory to make sure it's valid. Returns -1 if not, 0 else.
 */
int
set_global_vars(FILE *log, char *dir)
{
	struct stat info;

	/* Set log */
	gbl_log_file = log;
	
	/* Ensure directory given is valid */
	if (stat(dir, &info) != 0)
		return -1;
	if (!S_ISDIR(info.st_mode))
		return -1;

	/* Set directory */
	gbl_working_dir = dir;

	return 0;
}

/*
 * Retrieve all options from argc and argv with getopt, and place them in
 * values at the given pointers. Pointers must be allocated.
 * Returns the number of flags allocated.
 * Sets default values for the given options if flags are not specified.
 * Does all the address lookups and shit for you. Isn't that nice?
 *
 * Sets d_flag if we don't want to daemonize.
 * Sets results to a linked list of address results from getaddrinfo.
 * Sets log to the log to output to, or NULL if no log is desired.
 */
int
get_options(int argc, char **argv, int *d_flag, struct addrinfo **results,
    FILE **log)
{
	int c, ip_type, errcode;
	char *log_fname, *addr_name, *port_name;
	struct addrinfo settings;

	/* Set default values should flags be missing */
	ip_type = *d_flag = 0; /* 0 for ip_type = both */
	*log = NULL;
	log_fname = addr_name = port_name = NULL;

	/* Get options and set appropriate values */
	while ((c = getopt(argc, argv, "46da:l:p:")) != -1) {
		switch (c) {
		case '4': /* ipv4 only */
			ip_type = 4;
			break;
		case '6': /* ipv6 only */
			ip_type = 6;
			break;
		case 'a': /* specify log file */
			free(log_fname);
			if ((log_fname = strdup(optarg)) == NULL)
				err(1, "malloc");
			break;
		case 'd': /* do not daemonise */
			*d_flag = 1;
			break;
		case 'l': /* specify address to listen on */
			free(addr_name);
			if ((addr_name = strdup(optarg)) == NULL)
				err(1, "malloc");
			break;
		case 'p': /* specify port to listen on */
			free(port_name);
			if ((port_name = strdup(optarg)) == NULL)
				err(1, "malloc");
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Quit if no directory specified */
	if ((argc - optind) != 1)
		usage();

	/* Open log only if we are daemonising */
	if (log_fname != NULL && *d_flag != 1) {
		if ((*log = fopen(log_fname, "a")) == NULL)
			err(1, "%s", log_fname);
	}

	/* If not daemonising, then log to stdout */
	if (*d_flag == 1)
		*log = stdout;

	/* Setup address info settings */
	memset(&settings, 0, sizeof(settings));
	
	if (port_name == NULL)
		port_name = "http";
	if (addr_name == NULL)
		settings.ai_flags = AI_PASSIVE;
	settings.ai_family = AF_UNSPEC;
	if (ip_type == 4)
		settings.ai_family = AF_INET;
	else if (ip_type == 6)
		settings.ai_family = AF_INET6;
	settings.ai_socktype = SOCK_STREAM;
	settings.ai_protocol = IPPROTO_TCP;

	/* Get address info list based off these settings; error if bad */
	errcode = getaddrinfo(addr_name, port_name, &settings, results);
	if (errcode != 0)
		errx(1, gai_strerror(errcode));

	return optind;
}


/*
 * Given some address results from getaddrinfo, creates a socket for this
 * info, binds and listens non-blockingly on this socket. Errors on failure
 * for any of these steps. All addresses in results are tried for binding
 * before failurei.
 *
 * ip_type is the ip protocol to use: 4 or 6, or 0 if either.
 *
 * Returns the int for the socket desired.
 */
int
new_server_socket(struct addrinfo *results)
{
	struct addrinfo *r;
	int svr_fd;
	int on = 1;

	/* Loop through all results to find one which works */
	for (r = results; r != NULL; r = r->ai_next) {
		/* Go to next on socket/sockopt/bind failure */
		if ((svr_fd = socket(r->ai_family, r->ai_socktype,
		    r->ai_protocol)) == -1)
			continue;
		if (setsockopt(svr_fd, SOL_SOCKET, SO_REUSEADDR, &on,
		    sizeof(on)) == -1)
			continue;
		if (bind(svr_fd, r->ai_addr, r->ai_addrlen) == -1) {
			close(svr_fd);
			continue;
		}

		/* We only get here when socket/bind succeeds */
		break;
	}

	/* If r is NULL, we looped off the end of the list without success */
	if (r == NULL)
		err(1, "Create/bind socket failed (no permissions for port?)");
	
	/* Set this socket to non binding, and start listening */
	if (ioctl(svr_fd, FIONBIO, &on) == -1)
		err(1, "ioctl(FIONBIO) for listen");
	if (listen(svr_fd, 5) == -1)
		err(1, "listen");

	return svr_fd;
}

/*
 * mirrord [-46d] [-a access.log] [-l address] [-p port] directory
 */
int
main(int argc, char *argv[])
{
	int optnum, d_flag, svr_fd;
	struct addrinfo *results;
	struct event ev;
	FILE *log;

	/* Ignore the worthless SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	/* Get options ready; exit on bad number of args */
	if (argc < 2)
		usage();
	optnum = get_options(argc, argv, &d_flag, &results, &log);
	argc -= optnum;
	argv += optnum;

	/* Set global vars for working directories and logs */
	if (set_global_vars(log, argv[0]) != 0) 
		usage();

	/* all seems good; create server socket */
	svr_fd = new_server_socket(results);
	freeaddrinfo(results); /* no longer need results */

	/* daemonise if not told not to */
	if (d_flag != 1)
		daemon(1, 0); /* stay in directory; do close std */

	/* start server running process (events) */
	event_init();
	event_set(&ev, svr_fd, EV_READ | EV_PERSIST, on_conn_accept, NULL);
	event_add(&ev, NULL);

	event_dispatch();
	/* NOTREACHED */
	return 0;
}

