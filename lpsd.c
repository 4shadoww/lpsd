/*
  Copyright (C) 2022 Noa-Emil Nissinen

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.    If not, see <https://www.gnu.org/licenses/>.
*/

#define _XOPEN_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <limits.h>

// Extern arg functions
extern int print_help(const char*);
extern int print_version(const char*);
extern int arg_log_location(const char*);
extern int arg_date(const char*);
extern int arg_time_interval(const char*);
extern int arg_scans(const char*);
extern int arg_print_ports(const char*);
extern int arg_out(const char*);
extern int arg_stdin(const char*);
extern int arg_csv(const char*);

#define PROTOSIZE 10
#define IPSIZE 46

// Types for global variables
typedef char IP[IPSIZE];

typedef struct{
    unsigned int src;
    char proto[PROTOSIZE];
    unsigned short port;
    struct tm time;
}Record;

// Version
char g_version_string[] = "lpsd 1.0";

// Global variables
const char* g_program_name;
const char g_default_log_location[] = "/var/log/kern.log";
const char* g_log_location = g_default_log_location;
struct tm g_date;
int g_date_type = -1;
int g_interval = 5;
int g_cons = 5;
int g_print_ports = 0;
const char* g_out = NULL;
int g_read_stdin = 0;
int g_csv_format = 0;

// Variables to store parsed data
IP* g_ip_table;
unsigned int g_ip_table_len = 0;
unsigned int g_ip_table_items = 0;
Record* g_record_table;
unsigned int g_record_table_len = 0;
unsigned int g_record_table_items = 0;

typedef struct{
    unsigned short port;
    char* proto;
}PortProto;

time_t g_t;
struct tm g_time_now;

// Arg helper functions

unsigned int char_count(const char* str, const char c){
    unsigned int result = 0;
    unsigned int i = 0;
    while(str[i] != '\0'){
        if(str[i] == c) result++;
        i++;
    }
    return result;
}

const char* parse_time(const char* input, const char* format, struct tm* tm){
    memset (tm, '\0', sizeof(*tm));
    return strptime(input, format, tm);
}

typedef struct {
    char arg_long[25];
    char arg_short[5];
    int type;
    int (*fun_ptr)(const char*);
} Arg;

// Arguments without input (flags)
Arg args[] = {
// Long version, short version, type, function
{"--help",         "-h",           1,    &print_help},
{"--version",      "-v",           1,    &print_version},
{"--input-file",   "-i",           2,    &arg_log_location},
{"--date",         "-d",           2,    &arg_date},
{"--time-interval","-t",           2,    &arg_time_interval},
{"--scans",        "-s",           2,    &arg_scans},
{"--print-ports",  "-p",           1,    &arg_print_ports},
{"--out",          "-o",           2,    &arg_out},
{"--stdin",        "-si",          1,    &arg_stdin},
{"--csv-format",   "-csv",         1,    &arg_csv}
};

int print_help(const char* value){
    char options[] =
        "\nOptions:\n"
        "  -h,   --help\t\t\tprint help\n"
        "  -v,   --version\t\tprint version\n"
        "  -i,   --input-file <location>\tlog file location (kern.log)\n"
        "  -d,   --date <date>\t\tcheck logs from this date (format %Y-%m-%d, year is ignored)\n"
        "  -t,   --time-interval <time>\ttime interval in minutes (must be 1-60) (default 5 mins)\n"
        "  -s,   --scans <count>\t\tcount of opened connections to different ports (default 5)\n"
        "  -p,   --print-ports\t\tprint all ports\n"
        "  -o,   --out <file>\t\toutput to file\n"
        "  -si,  --stdin\t\t\tread from standard input (and not from file)\n"
        "  -csv, --csv-format\t\toutput in csv format";

    printf("usage: %s [OPTIONS...]\n%s\n", g_program_name, options);
    return -1;
}

int print_version(const char* value){
    printf("%s\n", g_version_string);
    return -1;
}

int arg_log_location(const char* value){
    g_log_location = value;
    return 0;
}

int arg_date(const char* value){
    unsigned int type = char_count(value, '-');
    const char* status = NULL;

    switch(type){
        case 2:
            status = parse_time(value, "%Y-%m-%d", &g_date);
            g_date_type = 2;
            break;
        case 1:
            status = parse_time(value, "%Y-%m", &g_date);
            g_date_type = 1;
            break;
        case 0:
            status = parse_time(value, "%Y", &g_date);
            g_date_type = 0;
            break;
    }

    if(status == NULL || *status != '\0'){
        fprintf(stderr, "error: invalid date \"%s\"\n", value);
        return 1;
    }

    return 0;
}

int arg_time_interval(const char* value){
    g_interval = atoi(value);
    if(g_interval <= 0 || g_interval > 60){
        fprintf(stderr, "error: invalid interval %s\nvalid values 1-60\n", value);
        return 1;
    }

    return 0;
}

int arg_scans(const char* value){
    g_cons = atoi(value);
    if(g_cons <= 0){
        fprintf(stderr, "error: invalid scans value \"%s\"\nmust be more than 0\n", value);
        return 1;
    }

    return 0;
}

int arg_print_ports(const char* value){
    g_print_ports = 1;
    return 0;
}

int arg_out(const char* value){
    g_out = value;
    return 0;
}

int arg_stdin(const char* value){
    g_read_stdin = 1;
    return 0;
}

int arg_csv(const char* value){
    g_csv_format = 1;
    return 0;
}

int get_substring(char* dest, unsigned int dest_len, const char* src, unsigned int start, unsigned int end){
    unsigned int len = end - start;
    if(len >= dest_len){
        fprintf(stderr, "error: regex match from %i to %i doesn't fit to buffer\n", start, end);
        return 1;
    }

    strncpy(dest, &src[start], len);
    dest[len] = '\0';

    return 0;
}

int initialise_tables(unsigned int ip_table_size, unsigned int record_table_size){
    g_ip_table = malloc(sizeof(IP)*ip_table_size);
    if(g_ip_table == NULL){
        fprintf(stderr, "error: failed to allocate memory for ip table\n");
        return 1;
    }
    g_record_table = malloc(sizeof(Record)*record_table_size);
    if(g_record_table == NULL){
        fprintf(stderr, "error: failed to allocate memory for record table\n");
    }

    g_ip_table_len = ip_table_size;
    g_record_table_len = record_table_size;

    return 0;
}

int deallocate_tables(){
    free(g_ip_table);
    free(g_record_table);
    return 0;
}

int setup_regex(regex_t* date_regex, regex_t* payload_regex){
    int status;

    status = regcomp(date_regex, "([a-z]{3} [0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2})", REG_EXTENDED | REG_ICASE);
    if(status != 0){
        fprintf(stderr, "failed to compile regex (%i)\n", status);
        return 1;
    }

    status = regcomp(payload_regex, " SRC=([^ ]+).*? PROTO=([^ ]+).*? DPT=([0-9]{1,5})", REG_EXTENDED | REG_ICASE);
    if(status != 0){
        fprintf(stderr, "failed to compile regex (%i)\n", status);
        return 1;
    }

    return 0;
}

int date_equal(const struct tm* date){
    switch(g_date_type){
        case 2:
            return (g_date.tm_mday == date->tm_mday && g_date.tm_mon == date->tm_mon);
        case 1:
            return (g_date.tm_mon == date->tm_mon);
        case 0:
            return 1;
    }

    return 0;
}

int parse_record(IP* ip, Record* record, const char* buffer, const regmatch_t* regex_match){
    int status;
    int temp_port;
    char match_buffer[IPSIZE];

    // Copy src
    status = get_substring(match_buffer, sizeof(match_buffer), buffer, regex_match[1].rm_so, regex_match[1].rm_eo);
    if(status != 0){
        return 1;
    }
    // No need to check does it fit because it's already checked in get_substring
    strcpy((char*)ip, match_buffer);

    // Copy proto
    status = get_substring(match_buffer, sizeof(match_buffer), buffer, regex_match[2].rm_so, regex_match[2].rm_eo);
    if(status != 0){
        return 1;
    }
    if(regex_match[2].rm_eo - regex_match[2].rm_so >= PROTOSIZE){
        fprintf(stderr, "error: protocol string doesn't fit\n");
        return 1;
    }
    strcpy(record->proto, match_buffer);

    // Copy port
    status = get_substring(match_buffer, sizeof(match_buffer), buffer, regex_match[3].rm_so, regex_match[3].rm_eo);
    if(status != 0){
        return 1;
    }
    temp_port = atoi(match_buffer);
    if(temp_port <= 0 && temp_port > USHRT_MAX){
        fprintf(stderr, "error: invalid port");
        return 1;
    }
    record->port = temp_port;

    return 0;
}

void* allocate_more_space(void* src, unsigned int element_size, unsigned int length, unsigned new_space){
    void* new_buffer = malloc(element_size*new_space);
    memcpy(new_buffer, src, element_size*length);
    free(src);

    return new_buffer;
}

int add_iprecord(const IP* ip, const Record* record){
    int ip_in_table = -1;
    unsigned int new_size;

    // Check does ip exist already in table
    for(unsigned int i = 0; i < g_ip_table_items; i++){
        if(strcmp((const char*)ip, g_ip_table[i]) == 0){
            ip_in_table = i;
            break;
        }
    }
    // Add if not already in table
    if(ip_in_table == -1){
        // Check is there enought space
        if(g_ip_table_len <= g_ip_table_items){
            new_size = g_ip_table_len + 50;
            g_ip_table = allocate_more_space(g_ip_table, sizeof(IP), g_ip_table_len, new_size);
            g_ip_table_len = new_size;
        }
        strcpy(g_ip_table[g_ip_table_items], (const char*)ip);
        ip_in_table = g_ip_table_items;
        g_ip_table_items++;
    }

    // Check is there enought space for record
    if(g_record_table_len <= g_record_table_items){
        new_size = g_record_table_len + 200;
        g_record_table = allocate_more_space(g_record_table, sizeof(Record), g_record_table_len, new_size);
        g_record_table_len = new_size;
    }

    g_record_table[g_record_table_items] = *record;
    g_record_table[g_record_table_items].src = ip_in_table;
    g_record_table_items++;

    return 0;
}

int get_timeval(struct tm* t1, struct tm* t2){
    // Cannot compute
    if(t1->tm_mon != t2->tm_mon) return -1;
    return ((t2->tm_mday - t1->tm_mday) * 1440) + ((t2->tm_hour - t1->tm_hour) * 60) + \
        (t2->tm_min - t1->tm_min);
}

PortProto* add_portproto(PortProto* ports, unsigned int* ports_len, unsigned int* ports_items, unsigned short port, char* proto){
    unsigned int new_size;
    // Check is the space
    if(*ports_len <= *ports_items){
        new_size = *ports_len + 20;
        ports = allocate_more_space(ports, sizeof(PortProto), *ports_len, new_size);
        *ports_len = new_size;
    }
    ports[*ports_items].port = port;
    ports[*ports_items].proto = proto;
    *ports_items = *ports_items + 1;

    return ports;
}

int port_in_list(PortProto* ports, unsigned int ports_len, unsigned short port){
    for(unsigned int i = 0; i < ports_len; i++){
        if(ports[i].port == port) return 1;
    }

    return 0;
}

int check_ip(unsigned int ip){
    // Ports and protocols
    unsigned int ports_len = 50;
    unsigned int ports_items = 0;
    PortProto* ports = malloc(sizeof(PortProto) * ports_len);

    struct tm* start_time;
    int timeval;
    unsigned int j;

    char timestr[11];

    for(unsigned int i = 0; i < g_record_table_items; i++){
        if(ip != g_record_table[i].src) continue;
        start_time = &g_record_table[i].time;

        ports = add_portproto(ports, &ports_len, &ports_items, g_record_table[i].port, g_record_table[i].proto);

        for(j = i+1; j < g_record_table_items; j++){
            if(ip != g_record_table[j].src) continue;
            // Check is timeval too great
            timeval = get_timeval(start_time, &g_record_table[j].time);
            if(timeval == 1 || timeval > g_interval) break;
            if(!port_in_list(ports, ports_items, g_record_table[j].port)){
                ports = add_portproto(ports, &ports_len, &ports_items, g_record_table[j].port, g_record_table[j].proto);
            }
        }
        if(ports_items >= g_cons){
            strftime(timestr, 11, "%Y-%m-%d", &g_record_table[i].time);
            if(g_csv_format){
                printf("%s,%s,%i\n", timestr, g_ip_table[g_record_table[i].src], ports_items);
            }else{
                printf("%s %s %i ports\n", timestr, g_ip_table[g_record_table[i].src], ports_items);
            }
            i = j-1;
        }
        // Reset
        ports_items = 0;
    }

    free(ports);
    return 0;
}

int check_log(){
    // File stream variables
    FILE* fp;
    char* buffer = NULL;
    size_t len = 0;
    unsigned int line_num = 0;

    // Regex variables
    int status;
    regex_t date_regex;
    regex_t payload_regex;
    regmatch_t regex_match[4];
    char match_buffer[IPSIZE];
    const char* time_status;

    // Parsing variables
    struct tm temp_time;
    IP temp_ip;
    Record temp_record;

    if(g_read_stdin){
        fp = stdin;
    }else{
        fp = fopen(g_log_location, "r");
    }

    // Open file
    if(fp == NULL && !g_read_stdin){
        fprintf(stderr, "error while opening file \"%s\"\n", g_log_location);
        perror("error");
        return 1;
    }else if(fp == NULL){
        fprintf(stderr, "error: stdin points to NULL\ncannot read user input\n");
        return 1;
    }

    // Set up regex
    if(setup_regex(&date_regex, &payload_regex) != 0){
        return 1;
    }
    if(initialise_tables(2000, 5000) != 0){
        return 1;
    }

    // Parse lines
    while(getline(&buffer, &len, fp) != -1){
        line_num++;

        // Date regex
        status = regexec(&date_regex, buffer, 1, regex_match, 0);
        if(status == REG_NOMATCH) continue;

        // Copy results
        status = get_substring(match_buffer, sizeof(match_buffer), buffer, regex_match[0].rm_so, regex_match[0].rm_eo);
        if(status != 0){
            fprintf(stderr, "error: invalid syntax in line %i\n", line_num);
            return 1;
        }

        // Parse time
        time_status = parse_time(match_buffer, "%b %d %H:%M:%S", &temp_time);
        if(time_status == NULL || *time_status != '\0'){
            fprintf(stderr, "error: failed to parse time \"%s\"\n", match_buffer);
        }
        // Skip if not the specified date
        if(g_date_type != -1 && date_equal(&temp_time) != 1) continue;

        // Payload regex
        status = regexec(&payload_regex, buffer, 4, regex_match, 0);
        if(status == REG_NOMATCH) continue;

        // Parse payload
        if(parse_record(&temp_ip, &temp_record, buffer, regex_match) != 0){
            fprintf(stderr, "error: invalid syntax in line %i\n", line_num);
            return 1;
        }
        temp_record.time = temp_time;
        // Assume the year to be current
        temp_record.time.tm_year = g_time_now.tm_year;

        add_iprecord(&temp_ip, &temp_record);
    }

    // Csv header
    if(g_csv_format){
        printf("scan_time,address,ports\n");
    }

    // TODO add threads
    // Find port scans
    for(unsigned int i = 0; i < g_ip_table_items; i++){
        check_ip(i);
    }

    fclose(fp);
    free(buffer);
    regfree(&date_regex);
    regfree(&payload_regex);
    deallocate_tables();

    return 0;
}

int main(int argc, char** argv){
    FILE* fp = NULL;

    g_program_name = argv[0];

    // Parse arguments
    for(int i = 1; i < argc; i++){
        int arg_parsed = 1;
        int success = 0;

        // Loop flag args
        for(unsigned int j = 0; j < sizeof(args)/sizeof(Arg); j++){
            if(strcmp(argv[i], args[j].arg_long) == 0 || strcmp(argv[i], args[j].arg_short) == 0){
                // Arg type 1
                if(args[j].type == 1){
                    success = args[j].fun_ptr(NULL);
                    arg_parsed = 0;
                    break;
                // Arg type 2
                }else if(args[j].type == 2){
                    // too few arguments
                    if(i+1 == argc){
                        fprintf(stderr, "error: too few arguments given\n");
                        print_help(NULL);
                        return 1;
                    }
                    success = args[j].fun_ptr(argv[i+1]);
                    arg_parsed = 0;
                    i++;
                    break;
                }
            }
        }
        if(arg_parsed != 0){
            fprintf(stderr, "error: unknown argument \"%s\"\n", argv[i]);
            return 1;
        }else if(success == -1){
            return 0;
        }else if(success != 0){
            return 1;
        }
    }

    g_t = time(NULL);
    g_time_now = *localtime(&g_t);

    // Output to file
    if(g_out != NULL){
        fp = freopen(g_out, "w", stdout);
        if(fp == NULL){
            fprintf(stderr, "error while opening output file \"%s\"\n", g_out);
            perror("error");
            return 1;
        }
    }

    if(check_log() != 0){
        return 1;
    }

    if(g_out != NULL){
        fclose(fp);
    }

    return 0;
}
