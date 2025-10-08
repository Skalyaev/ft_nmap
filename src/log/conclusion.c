#include "../../include/header.h"

static void port_scan_reorder(t_scan* const result) {

    t_port_state tmp = {0};

    for(uint16_t x = 0; result->ports[x].port; x++) {
        for(uint16_t y = x + 1; result->ports[y].port; y++) {

            if(result->ports[x].port < result->ports[y].port) continue;

            memcpy(&tmp, &result->ports[x], T_PORT_STATE_SIZE);
            memcpy(&result->ports[x], &result->ports[y], T_PORT_STATE_SIZE);
            memcpy(&result->ports[y], &tmp, T_PORT_STATE_SIZE);
        }
    }
}

void port_scan_conclusion(t_scan* const result) {

    port_scan_reorder(result);

    t_port_state* port_state = NULL;
    for(uint16_t x = 0; result->ports[x].port; x++) {

        port_state = &result->ports[x];

        if(port_state->syn_scan_state == PORT_OPEN ||
           port_state->connect_scan_state == PORT_OPEN ||
           port_state->udp_scan_state == PORT_OPEN) {

            port_state->conclusion = PORT_OPEN;
        }
        else if(port_state->syn_scan_state == PORT_FILTERED ||
                port_state->connect_scan_state == PORT_FILTERED ||
                port_state->ack_scan_state == PORT_FILTERED ||
                port_state->udp_scan_state == PORT_FILTERED) {

            port_state->conclusion = PORT_FILTERED;
        }
        else if(port_state->syn_scan_state == PORT_CLOSED ||
                port_state->connect_scan_state == PORT_CLOSED ||
                port_state->udp_scan_state == PORT_CLOSED) {

            port_state->conclusion = PORT_CLOSED;
        }
        else if(port_state->maimon_scan_state == PORT_OPEN ||
                port_state->window_scan_state == PORT_OPEN) {

            port_state->conclusion = PORT_OPEN;
        }
        else if(port_state->maimon_scan_state == PORT_FILTERED ||
                port_state->window_scan_state == PORT_FILTERED ||
                port_state->fin_scan_state == PORT_FILTERED ||
                port_state->null_scan_state == PORT_FILTERED ||
                port_state->xmas_scan_state == PORT_FILTERED) {

            port_state->conclusion = PORT_FILTERED;
        }
        else if(port_state->window_scan_state == PORT_CLOSED ||
                port_state->fin_scan_state == PORT_CLOSED ||
                port_state->null_scan_state == PORT_CLOSED ||
                port_state->xmas_scan_state == PORT_CLOSED) {

            port_state->conclusion = PORT_CLOSED;
        }
        else if(port_state->fin_scan_state == PORT_OPEN_FILTERED ||
                port_state->null_scan_state == PORT_OPEN_FILTERED ||
                port_state->xmas_scan_state == PORT_OPEN_FILTERED ||
                port_state->udp_scan_state == PORT_OPEN_FILTERED) {

            port_state->conclusion = PORT_OPEN;
        }
        else port_state->conclusion = PORT_UNFILTERED;
    }
}
