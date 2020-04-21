#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/socket.h>

const char *argp_program_version = "cping 1.0";
const char *argp_program_bug_address = "<horkay.matyas@gmail.com>";

static char doc[] = "A small ping CLI application to send ICMP echo requests in a loop";

static char args_doc[] = "-t TARGET_HOSTNAME\n-i TARGET_IP";

static struct argp_option options[] = {
	{"target_host", 't', "HOSTNAME", 0, "Specify target by HOSTNAME"},
	{"target_ip", 'i', "IP", 0, "Specify target by IP"},
	{0}
};

struct arguments {
	char *target_hostname;
	char *target_ip;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	
	struct arguments *arguments = state->input;
	switch(key) {
		case 't':
			if (arguments->target_ip != "") {
				printf("Please only specify either the HOSTNAME or IP\n");
				argp_usage(state);
			}
			arguments->target_hostname = arg;
			break;

		case 'i':
			if (arguments->target_hostname != "") {
				printf("Please only specify either the HOSTNAME or IP\n");
				argp_usage(state);
			}
			arguments->target_ip = arg;
			break;

		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char **argv) {
	struct arguments arguments;

	arguments.target_hostname = "";
	arguments.target_ip = "";

	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	printf("HOSTNAME = %s\nIP = %s\n", arguments.target_hostname, arguments.target_ip);

	exit(0);

}

