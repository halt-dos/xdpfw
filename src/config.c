#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <string.h>
#include <linux/types.h>

#include <arpa/inet.h>

#include "xdpfw.h"
#include "config.h"

FILE *file;

/**
 * Sets the config structure's default values.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
*/
void setcfgdefaults(struct config *cfg)
{
    cfg->updatetime = 0;
    cfg->interface = "eth0";
    cfg->nostats = 0;

    for (__u16 i = 0; i < MAX_FILTERS; i++)
    {
        cfg->filters[i].id = 0;
        cfg->filters[i].enabled = 0;
        cfg->filters[i].action = 0;
        cfg->filters[i].srcip = 0;
        cfg->filters[i].dstip = 0;

        for (__u8 j = 0; j < 4; j++)
        {
            cfg->filters[i].srcip6[j] = 0;
            cfg->filters[i].dstip6[j] = 0;
        }

        cfg->filters[i].do_min_len = 0;
        cfg->filters[i].min_len = 0;

        cfg->filters[i].do_max_len = 0;
        cfg->filters[i].max_len = 65535;

        cfg->filters[i].do_min_ttl = 0;
        cfg->filters[i].min_ttl = 0;

        cfg->filters[i].do_max_ttl = 0;
        cfg->filters[i].max_ttl = 255;

        cfg->filters[i].do_tos = 0;
        cfg->filters[i].tos = 0;

        cfg->filters[i].do_pps = 0;
        cfg->filters[i].pps = 0;
        
        cfg->filters[i].do_bps = 0;
        cfg->filters[i].bps = 0;

        cfg->filters[i].blocktime = 1;
        
        cfg->filters[i].tcpopts.enabled = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_urg = 0;
        cfg->filters[i].tcpopts.do_ack = 0;
        cfg->filters[i].tcpopts.do_rst = 0;
        cfg->filters[i].tcpopts.do_psh = 0;
        cfg->filters[i].tcpopts.do_syn = 0;
        cfg->filters[i].tcpopts.do_fin = 0;
        cfg->filters[i].tcpopts.do_ece = 0;
        cfg->filters[i].tcpopts.do_cwr = 0;

        cfg->filters[i].udpopts.enabled = 0;
        cfg->filters[i].udpopts.do_sport = 0;
        cfg->filters[i].udpopts.do_dport = 0;

        cfg->filters[i].icmpopts.enabled = 0;
        cfg->filters[i].icmpopts.do_code = 0;
        cfg->filters[i].icmpopts.do_type = 0;
    }
}

/**
 * Opens the config file.
 * 
 * @param filename Path to config file.
 * 
 * @return 0 on success or 1 on error.
*/
int opencfg(const char *filename)
{
    // Close any existing files.
    if (file != NULL)
    {
        fclose(file);

        file = NULL;
    }

    file = fopen(filename, "r");

    if (file == NULL)
    {
        return 1;
    }

    return 0;
}

int readcfg(struct config *cfg, const char *filename)
{
    // Not sure why this would be set to NULL after checking for it in OpenConfig(), but just for safety.
    if (file == NULL)
    {
        return -1;
    }

    json_t *root;
    json_error_t error;

    // Load the JSON file
    root = json_load_file(filename, 0, &error);
    if (!root) {
        fprintf(stderr, "Error reading JSON file: %s\n", error.text);
        return 1;
    }

    // Get Interface.
    const char *interface = "interface";
    json_t *value = json_object_get(root, interface);
    if (value == NULL) {
        fprintf(stderr, "Error when reading 'interface' setting - %s\n\n", interface);
        return 1; 
    }

    const char *interface_value = json_string_value(value);
    cfg->interface = strdup(interface_value);

    // Get auto update time.
    const char *updatetime = "updatetime";
    value = json_object_get(root, updatetime);
    if (value == NULL) {
        fprintf(stderr, "Error when reading 'updatetime' setting - %s\n\n", updatetime);
        return 1; 
    }

    cfg->updatetime = json_integer_value(value);
    
    // Get no stats.
    const char *nostats = "nostats";
    value = json_object_get(root, nostats);
    if (value != NULL) {
        cfg->nostats = json_is_true(value);
    }

    // Read filters in filters_map structure.
    json_t *filters = json_object_get(root, "filters");

    if (!json_is_array(filters)) {
        fprintf(stderr, "Error getting filters from JSON file.\n");
        return 1;
    }

    // Set filter count.
    int count = 0;

    size_t size = json_array_size(filters);

    for (size_t i = 0; i < size; i++)
    {
        json_t *filter = json_array_get(filters, i);

        // Enabled (required)
        int enabled = 0;
        if (json_object_get(filter, "enabled") == NULL) {
            fprintf(stderr, "Error getting enabled from filter.\n");
            continue;
        }

        cfg->filters[i].enabled = json_boolean_value(json_object_get(filter, "enabled"));

        // Action (required).
        int action;
        if (json_object_get(filter, "action") == NULL) {
            fprintf(stderr, "Error getting action from filter.\n");
            continue;
        }

        cfg->filters[i].action = json_boolean_value(json_object_get(filter, "action"));

        // Source IP (not required).
        const char *sip = json_string_value(json_object_get(filter, "srcip"));
        if (sip) {
            cfg->filters[i].srcip = inet_addr(sip);
        }

        // Destination IP (not required).
        const char *dip = json_string_value(json_object_get(filter, "dstip"));
        if (dip) {
            cfg->filters[i].dstip = inet_addr(dip);
        }

        // Source IP (IPv6) (not required).
        const char *sip6 = json_string_value(json_object_get(filter, "srcip6"));
        if (sip6) {
            struct in6_addr in;
            inet_pton(AF_INET6, sip6, &in);
            for (__u8 j = 0; j < 4; j++)
            {
                cfg->filters[i].srcip6[j] = in.__in6_u.__u6_addr32[j];
            }
        }

        // Destination IP (IPv6) (not required).
        const char *dip6 = json_string_value(json_object_get(filter, "dstip6"));
        if (dip6) {
            struct in6_addr in;
            inet_pton(AF_INET6, dip6, &in);
            for (__u8 j = 0; j < 4; j++)
            {
                cfg->filters[i].dstip6[j] = in.__in6_u.__u6_addr32[j];
            }
        }

        cfg->filters[i].tcpopts.enabled = json_boolean_value(json_object_get(filter, "tcp_enabled"));

        long long tcpdport = json_integer_value(json_object_get(filter, "tcp_dport"));
        if (tcpdport) {
            cfg->filters[i].tcpopts.dport = (__u16)tcpdport;
            cfg->filters[i].tcpopts.do_dport = 1;
        }

        long long tcpsport = json_integer_value(json_object_get(filter, "tcp_sport"));
        if (tcpsport) {
            cfg->filters[i].tcpopts.dport = (__u16)tcpsport;
            cfg->filters[i].tcpopts.do_dport = 1;
        }

        // Assign ID and increase filter count.
        cfg->filters[i].id = ++count;
    }

    json_decref(root);
    fclose(file);
    return 0;
}