#include "../../include/header.h"

extern t_nmap data;

static uint16_t get_ainsi_strlen(const char* str) {

	uint16_t len = 0;
    for(const unsigned char* ptr = (const unsigned char*)str; *ptr;) {

        if(*ptr == '\x1b' && *(ptr + 1) == '[') {

            ptr += 2;
            while(*ptr && (*ptr < 0x40 || *ptr > 0x7E)) ptr++;

            if(*ptr) ptr++;
            continue;
        }
        if(*ptr == '\x1b') {

            ptr++;
            if(*ptr) ptr++;
            continue;
        }
        len++;
        ptr++;
    }
	return len;
}

static void print_ainsi(const char* str, uint16_t width) {

	const uint16_t size = get_ainsi_strlen(str);

    printf("%s", str);
    if(width <= size) return;

	for(uint16_t x = 0; x < width - size; x++) printf(" ");
}

static const char* state_to_str(const uint8_t state) {

    switch(state) {

        case PORT_OPEN: 
            return GREEN"Open"RST;

        case PORT_CLOSED: 
            return RED"Closed"RST;

        case PORT_FILTERED: 
            return YELLOW"Filtered"RST;

        case PORT_UNFILTERED:
            return GREEN"Unfiltered"RST;

        case PORT_OPEN_FILTERED: 
            return YELLOW"Open"RST"|"YELLOW"Filtered"RST;

        case PORT_CLOSED_FILTERED:
            return YELLOW"Closed"RST"|"YELLOW"Filtered"RST;
    }
    return "Unknown";
}

static int8_t scan_report_states(const t_port_state* const port_state,
                                 const uint16_t width,
								 char** const states) {

	const char* const scan_names[] = {

		"SYN", "NULL", "FIN", "XMAS", "ACK",
		"CONNECT", "WINDOW", "MAIMON", "UDP"
	};
	const uint16_t scan_flags[] = {

		SYN_SCAN, NULL_SCAN, FIN_SCAN, XMAS_SCAN, ACK_SCAN,
		CONNECT_SCAN, WINDOW_SCAN, MAIMON_SCAN, UDP_SCAN
	};
	const uint8_t scan_count = sizeof(scan_names) / PTR_SIZE;

	char scans[scan_count][BUFFER_SIZE + 1];
    memset(scans, 0, sizeof(scans));

	uint16_t count = 0;
	uint8_t state;

	for(uint8_t x = 0; x < scan_count; x++) {

		if(!(data.opt.flags & scan_flags[x])) continue;
		switch(x) {

			case 0: state = port_state->syn_scan_state; break;
			case 1: state = port_state->null_scan_state; break;
			case 2: state = port_state->fin_scan_state; break;
			case 3: state = port_state->xmas_scan_state; break;
			case 4: state = port_state->ack_scan_state; break;
			case 5: state = port_state->connect_scan_state; break;
			case 6: state = port_state->window_scan_state; break;
			case 7: state = port_state->maimon_scan_state; break;
			case 8: state = port_state->udp_scan_state; break;
		}
		snprintf(scans[count], BUFFER_SIZE, "%s(%s)",
                 scan_names[x], state_to_str(state));

		if(++count == scan_count) break;
	}
	char* line = NULL;
	char* word = NULL;

	uint16_t line_size;
	uint16_t word_size;
	uint16_t line_ainsi_size;
	uint16_t word_ainsi_size;

	uint16_t scan_idx = 0;
	uint16_t line_idx = 0;
	while(scan_idx < count) {

		line = malloc(BUFFER_SIZE + 1);
		if(!line) {

			for(uint16_t x = 0; x < line_idx; x++) {

				free(states[x]);
				states[x] = NULL;
			}
			return FAILURE;
		}
		memset(line, 0, BUFFER_SIZE + 1);

		line_size = 0;
		line_ainsi_size = 0;
		while(scan_idx < count) {

			word = scans[scan_idx];
			word_size = strlen(word);
			word_ainsi_size = get_ainsi_strlen(word);

			if(line_ainsi_size + word_ainsi_size + 1 > width) break;
			if(line_ainsi_size) {

				line[line_size++] = ' ';
				line_ainsi_size++;
			}
			if(line_size + word_size >= BUFFER_SIZE)break;

			memcpy(line + line_size, word, word_size);
			line_size += word_size;
			line_ainsi_size += word_ainsi_size;

			scan_idx++;
		}
		line[line_size] = '\0';
		states[line_idx++] = line;
	}
	return SUCCESS;
}

static void scan_report_service(const t_port_state* const port_state,
							    const uint16_t width,
							    char* const service) {

	const char* const txt = port_state->service;
	uint16_t size = strlen(txt);

	if(size <= width) {

		snprintf(service, BUFFER_SIZE + 1, "%s", txt);
		return;
	}
	if(width <= 3) {

		uint16_t fill_count = width < BUFFER_SIZE ? width : BUFFER_SIZE;

		for(uint16_t x = 0; x < fill_count; x++) service[x] = '.';
		service[fill_count] = '\0';
		return;
	}
	uint16_t copy_len = width - 3;
	if(copy_len > BUFFER_SIZE - 3) copy_len = BUFFER_SIZE - 3;

	snprintf(service, BUFFER_SIZE + 1, "%.*s...", copy_len, txt);
}

static void scan_report_conclusion(const t_port_state* const port_state,
                                   char* const conclusion) {

    if(port_state->conclusion == PORT_OPEN) {

		snprintf(conclusion, BUFFER_SIZE + 1, GREEN"Open"RST);
        return;
    }
    if(port_state->conclusion == PORT_CLOSED) {

		snprintf(conclusion, BUFFER_SIZE + 1, RED"Closed"RST);
        return;
    }
    if(port_state->conclusion == PORT_FILTERED) {

		snprintf(conclusion, BUFFER_SIZE + 1, YELLOW"Filtered"RST);
        return;
    }
    if(port_state->conclusion == PORT_UNFILTERED) {

		snprintf(conclusion, BUFFER_SIZE + 1, YELLOW"Unfiltered"RST);
        return;
    }
}

static void scan_report_separator(const uint16_t* const width) {

    const uint16_t full_width = width[0] + width[1] +
                                width[0] + width[2] +
                                width[0] + width[3] + width[4];

    for(uint16_t x = 0; x < full_width; x++) printf(GRAY"="RST);
    printf("\n");
}

static void scan_report_line(const uint16_t* const width,
                             char* const* str) {

	print_ainsi(str[0], width[1]);
	printf("%*s", width[0], "");
	print_ainsi(str[1], width[2]);
	printf("%*s", width[0], "");
	print_ainsi(str[2], width[3]);
	printf("%*s", width[0], "");
	print_ainsi(str[3], width[4]);
	printf("\n");
}

static void port_scan_report(t_scan* const result) {

    uint16_t free_width = 0;
    t_winsize winsize = {0};

    if(!ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize))
        free_width = winsize.ws_col;

    if(!free_width) free_width = 120;

    const uint8_t gap_width = 2;
    const uint8_t port_width = 8;
    const uint8_t state_width = 12;

    free_width = free_width - port_width - state_width - (gap_width * 3);
    if(free_width < 20) free_width = 20;

    uint16_t service_width = free_width / 3;
    if(service_width < 8) service_width = 8;

    uint16_t scans_width = free_width - service_width;
    if(scans_width < 12) scans_width = 12;

    const uint16_t width[5] = {

        gap_width, port_width, service_width, scans_width, state_width
    };
    char* line[4] = {

        BOLD"PORT"RST, BOLD"SERVICE"RST,
        BOLD"SCANS"RST, BOLD"STATE"RST
    };
    scan_report_line(width, line);
    scan_report_separator(width);

    t_port_state* port_state = NULL;

    char* states[BUFFER_SIZE + 1] = {0};
    char service[BUFFER_SIZE + 1] = {0};
    char conclusion[BUFFER_SIZE + 1] = {0};
    char port[16] = {0};

    const uint32_t states_size = sizeof(states);
    const uint32_t service_size = sizeof(service);
    const uint32_t conclusion_size = sizeof(conclusion);
    const uint32_t port_size = sizeof(port);

    for(uint8_t x = 0; x < 2; x++) {

        for(uint16_t y = 0; result->ports[y].port; y++) {

            port_state = &result->ports[y];

            if(!x && port_state->conclusion != PORT_OPEN) continue;
            if(x && port_state->conclusion == PORT_OPEN) continue;

			if(scan_report_states(port_state, scans_width,
							      states) == FAILURE) {
                setcode(errno);
                error(strerror(errno));
                return;
            }
			scan_report_service(port_state, service_width, service);
			scan_report_conclusion(port_state, conclusion);

            for(uint16_t z = 0; states[z]; z++) {

				if(!z) {
                    snprintf(port, port_size, "%u", port_state->port);

					line[0] = port;
					line[1] = service;
					line[2] = states[z];
					line[3] = conclusion;
				}
                else {
                    line[0] = "";
                    line[1] = "";
                    line[2] = states[z];
                    line[3] = "";
                }
                scan_report_line(width, line);

                free(states[z]);
                states[z] = NULL;
            }
            scan_report_separator(width);

			memset(states, 0, states_size);
			memset(service, 0, service_size);
			memset(conclusion, 0, conclusion_size);
            memset(port, 0, port_size);
        }
    }
}

void outro() {

    pthread_mutex_lock(&data.output_mutex);
    pthread_mutex_lock(&data.results_mutex);

    printf("\n");
    printf(GRAY""BOLD"#=============#"RST"\n");
    printf(GRAY""BOLD"# SCAN RESULT #"RST"\n");
    printf(GRAY""BOLD"#=============#"RST"\n");

    for(t_scan* result = data.results; result; result = result->next) {

        printf("\n");
        printf("IP\t\t");
        printf(BOLD"%s"RST"\n", result->ip);

        if(result->domain) {

            printf("Domain\t\t");
            printf(BOLD"%s"RST"\n", result->domain);
        }
        printf("Status\t\t");
        if(result->up) printf(GREEN""BOLD"UP"RST"\n");
        else printf(RED""BOLD"DOWN"RST"\n");

        if(result->os) {

            printf("OS\t\t");
            printf(BOLD"%s"RST"\n", result->os);
        }
        printf("\n");

        port_scan_services(result);
        port_scan_conclusion(result);
        port_scan_report(result);
    }
    printf("\n");
    pthread_mutex_unlock(&data.results_mutex);
    pthread_mutex_unlock(&data.output_mutex);
}
