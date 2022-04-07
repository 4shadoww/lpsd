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
#include<unistd.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>

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

typedef struct{
    unsigned short port;
    char* proto;
}PortProto;

typedef struct{
    PortProto* table;
    unsigned int items;
    unsigned int len;

}ConnTable;

typedef struct{
    char* buffer;
    unsigned int chars;
    unsigned int len;
}PortStr;

typedef struct{
    unsigned int start;
    unsigned int end;
} SubStr;

typedef struct{
    int stage;
    int keyword_index;
    int start;
    int end;
}FinderStatus;

typedef struct{
    int8_t status;
    SubStr src;
    SubStr proto;
    SubStr port;
}PayloadSubStr;

struct{
    IP* table;
    unsigned int items;
    unsigned int len;
} g_ip_table;


struct{
    Record* table;
    unsigned int items;
    unsigned int len;

} g_record_table;

// Version
char g_version_string[] = "lpsd pre-1.0";

// Global variables
const char* g_program_name;
unsigned int g_log_count = 1;
const char** g_log_location;
struct tm g_date;
int g_date_type = -1;
int g_interval = 5;
int g_cons = 5;
int g_print_ports = 0;
const char* g_out = NULL;
int g_read_stdin = 0;
int g_csv_format = 0;

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

void copy_file_names(const char* str){
    const char delimiter = ',';
    unsigned int i = 0;
    unsigned int begin = 0;
    unsigned int str_len;
    unsigned int str_num = 0;
    char* temp;

    while(str[i] != '\0'){
        if(str[i] == delimiter){
            str_len = i - begin + 1;
            temp = malloc(sizeof(char)*str_len);
            strncpy(temp, str+begin, str_len);
            temp[str_len-1] = '\0';
            g_log_location[str_num] = temp;
            str_num++;
            begin = i + 1;
        }
        i++;
    }
    // Copy the remaining
    str_len = i - begin + 1;
    temp = malloc(sizeof(char)*str_len);
    strncpy(temp, str+begin, str_len);
    temp[str_len-1] = '\0';
    g_log_location[str_num] = temp;
}

const char* parse_time(const char* input, const char* format, struct tm* tm){
    memset(tm, '\0', sizeof(*tm));
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
        "  -i,   --input-file <file(s)>\tlog file(s) (kern.log) delimiter: comma (,)\n\t\t\t\tfiles must be given in ascending order (also the log entries) (see the man page)\n"
        "  -d,   --date <date>\t\tcheck logs from this date (format %Y-%m-%d, year is ignored)\n"
        "  -t,   --time-interval <time>\ttime interval in minutes (must be 1-60) (default 5 mins)\n"
        "  -s,   --scans <count>\t\tcount of opened connections to different ports (default 5)\n"
        "  -p,   --print-ports\t\tprint all ports\n"
        "  -o,   --out <file>\t\toutput to file\n"
        "  -si,  --stdin\t\t\tread from standard input (must be ascending)\n"
        "  -csv, --csv-format\t\toutput in csv format";

    printf("usage: %s [OPTIONS...] -i <log_file> \n%s\n", g_program_name, options);
    return -1;
}

int print_version(const char* value){
    printf("%s\n", g_version_string);
    return -1;
}

int arg_log_location(const char* value){
    unsigned int file_count = char_count(value, ',') + 1;
    if(file_count == 1){
        g_log_location[0] = value;
        return 0;
    }
    g_log_count = file_count;
    g_log_location = malloc(sizeof(char*)*file_count);
    copy_file_names(value);

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
        fprintf(stderr, "error: match from %i to %i doesn't fit to buffer\n", start, end);
        return 1;
    }

    strncpy(dest, &src[start], len);
    dest[len] = '\0';

    return 0;
}

int initialise_tables(unsigned int ip_table_size, unsigned int record_table_size){
    g_ip_table.len = ip_table_size;
    g_ip_table.items = 0;
    g_ip_table.table = malloc(sizeof(IP)*ip_table_size);
    if(g_ip_table.table == NULL){
        fprintf(stderr, "error: failed to allocate memory for ip table\n");
        return 1;
    }

    g_record_table.len = record_table_size;
    g_record_table.items = 0;
    g_record_table.table = malloc(sizeof(Record)*record_table_size);
    if(g_record_table.table == NULL){
        fprintf(stderr, "error: failed to allocate memory for record table\n");
    }

    g_ip_table.len = ip_table_size;
    g_record_table.len = record_table_size;

    return 0;
}

int deallocate_tables(){
    free(g_ip_table.table);
    free(g_record_table.table);
    return 0;
}

int find_stage(char* buffer, unsigned int i, FinderStatus* fs, PayloadSubStr* result, const char* keyword, const unsigned int keyword_len, char delimiter){
    // Null check
    if(buffer[i] == '\0'){
        fs->end = i - 1;
        return -1;
    }

    // Find value
    if(keyword_len <= fs->keyword_index){
        if(tolower(buffer[i]) == delimiter){
            fs->stage++;
            fs->end = i;
            return 1;
        }

    // Find keyword
    }else if(keyword[fs->keyword_index] == tolower(buffer[i])){
        fs->keyword_index++;
        if(fs->keyword_index == keyword_len){
            fs->start = i + 1;
        }

    // Doesn't match, reset
    }else{
        fs->keyword_index = 0;
    }

    return 0;
}

// TODO This is kind of mess
// try to find more clean solution
PayloadSubStr find_payload(char* input, unsigned int size){
    PayloadSubStr result;
    FinderStatus fs;

    const char keyword1[] = " src=";
    const char keyword2[] = " proto=";
    const char keyword3[] = " dpt=";
    int status;

    fs.stage = 0;
    fs.keyword_index = 0;
    fs.start = 0;
    fs.end = 0;

    result.status = 0;

    for(unsigned int i = 0;; i++){
        switch(fs.stage){
            // Find src=
            case 0:
                status = find_stage(input, i, &fs, &result, keyword1, 5, ' ');
                // EOS
                if(status == -1) return result;
                // Found
                else if(status == 1){
                    result.src.start = fs.start;
                    result.src.end = fs.end;
                    fs.keyword_index = 0;
                }
                break;
            // Find proto=
            case 1:
                status = find_stage(input, i, &fs, &result, keyword2, 7, ' ');
                // EOS
                if(status == -1) return result;
                // Found
                else if(status == 1){
                    result.proto.start = fs.start;
                    result.proto.end = fs.end;
                    fs.keyword_index = 0;
                }
                break;
            // Find dpt=
            case 2:
                status = find_stage(input, i, &fs, &result, keyword3, 5, ' ');
                // EOS
                if(status == -1){
                    if(fs.keyword_index == 4){
                        result.status = 1;
                        result.port.start = fs.start;
                        result.port.end = fs.end;
                    }

                    return result;
                // Found
                }else if(status == 1){
                    result.port.start = fs.start;
                    result.port.end = fs.end;
                    result.status = 1;
                    return result;
                }

                break;
        }
    }

    return result;
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

int parse_record(IP* ip, Record* record, const char* buffer, const PayloadSubStr* match){
    int status;
    int temp_port;
    char match_buffer[IPSIZE];

    // Copy src
    status = get_substring(match_buffer, sizeof(match_buffer), buffer, match->src.start, match->src.end);
    if(status != 0){
        return 1;
    }
    // No need to check does it fit because it's already checked in get_substring
    strcpy((char*)ip, match_buffer);

    // Copy proto
    status = get_substring(match_buffer, sizeof(match_buffer), buffer, match->proto.start, match->proto.end);
    if(status != 0){
        return 1;
    }
    if(match->proto.end - match->proto.start >= PROTOSIZE){
        fprintf(stderr, "error: protocol string doesn't fit\n");
        return 1;
    }
    strcpy(record->proto, match_buffer);

    // Copy port
    status = get_substring(match_buffer, sizeof(match_buffer), buffer, match->port.start, match->port.end);
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
    for(unsigned int i = 0; i < g_ip_table.items; i++){
        if(strcmp((const char*)ip, g_ip_table.table[i]) == 0){
            ip_in_table = i;
            break;
        }
    }
    // Add if not already in table
    if(ip_in_table == -1){
        // Check is there enought space
        if(g_ip_table.len <= g_ip_table.items){
            new_size = g_ip_table.len + 50;
            g_ip_table.table = allocate_more_space(g_ip_table.table, sizeof(IP), g_ip_table.len, new_size);
            g_ip_table.len = new_size;
        }
        strcpy(g_ip_table.table[g_ip_table.items], (const char*)ip);
        ip_in_table = g_ip_table.items;
        g_ip_table.items++;
    }

    // Check is there enought space for record
    if(g_record_table.len <= g_record_table.items){
        new_size = g_record_table.len + 200;
        g_record_table.table = allocate_more_space(g_record_table.table, sizeof(Record), g_record_table.len, new_size);
        g_record_table.len = new_size;
    }

    g_record_table.table[g_record_table.items] = *record;
    g_record_table.table[g_record_table.items].src = ip_in_table;
    g_record_table.items++;

    return 0;
}

int get_timeval(struct tm* t1, struct tm* t2){
    return ((t2->tm_year - t1->tm_year) * 525949) + ((t2->tm_mon - t1->tm_mon) * 43829) + \
        ((t2->tm_mday - t1->tm_mday) * 1440) + ((t2->tm_hour - t1->tm_hour) * 60) + \
        (t2->tm_min - t1->tm_min);
}

void add_portproto(ConnTable* conn_table, unsigned short port, char* proto){
    unsigned int new_size;
    // Check is the space
    if(conn_table->len <= conn_table->items){
        new_size = conn_table->len + 20;
        conn_table->table = allocate_more_space(conn_table->table, sizeof(PortProto), conn_table->len, new_size);
        conn_table->len = new_size;
    }
    conn_table->table[conn_table->items].port = port;
    conn_table->table[conn_table->items].proto = proto;
    conn_table->items++;
}

int port_in_list(ConnTable* conn_table, unsigned short port){
    for(unsigned int i = 0; i < conn_table->items; i++){
        if(conn_table->table[i].port == port) return 1;
    }

    return 0;
}

void create_port_list(PortStr* port_str, ConnTable* conn_table){
    char temp[PROTOSIZE + 5 + 4];
    unsigned int temp_len;
    unsigned int new_size;

    for(unsigned int i = 0; i < conn_table->items; i++){
        if(i+1 == conn_table->items){
            sprintf(temp, "%s/%i", conn_table->table[i].proto, conn_table->table[i].port);
            temp_len = strlen(temp);
            if(port_str->len - port_str->chars < PROTOSIZE + 5 + 4){
                new_size = port_str->len + 100;
                port_str->buffer = allocate_more_space(port_str->buffer, sizeof(char), port_str->len, new_size);
                port_str->len = new_size;
            }
            // Use memcpy insted of strncpy to silence annoying warnings
            memcpy(port_str->buffer+(port_str->chars), temp, temp_len);
            port_str->chars = port_str->chars + temp_len;
        }else{
            sprintf(temp, "%s/%i, ", conn_table->table[i].proto, conn_table->table[i].port);
            temp_len = strlen(temp);
            if(port_str->len - port_str->chars < PROTOSIZE + 5 + 4){
                new_size = port_str->len + 100;
                port_str->buffer = allocate_more_space(port_str->buffer, sizeof(char), port_str->len, new_size);
                port_str->len = new_size;
            }
            // Use memcpy insted of strncpy to silence annoying warnings
            memcpy(port_str->buffer+(port_str->chars), temp, temp_len);
            port_str->chars = port_str->chars + temp_len;
        }
    }
    if(port_str->len <= port_str->chars){
        new_size = port_str->len + 100;
        port_str->buffer = allocate_more_space(port_str->buffer, sizeof(char), port_str->len, new_size);
        port_str->len = new_size;
    }
    port_str->buffer[port_str->chars] = '\0';
    port_str->chars++;
}


void form_port_string(PortStr* port_str, ConnTable* conn_table){
    if(g_csv_format){
        if(g_print_ports){
            create_port_list(port_str, conn_table);
        }else{
            sprintf(port_str->buffer, "%i", conn_table->items);
        }

    }else{
        if(g_print_ports){
            create_port_list(port_str, conn_table);
        }else{
            sprintf(port_str->buffer, "%i ports", conn_table->items);
        }
    }
}

int check_ip(unsigned int ip, ConnTable* conn_table, PortStr* port_str){
    struct tm* start_time;
    int timeval;
    unsigned int j;

    char timestr[20];

    for(unsigned int i = 0; i < g_record_table.items; i++){
        if(ip != g_record_table.table[i].src) continue;
        start_time = &g_record_table.table[i].time;

        add_portproto(conn_table, g_record_table.table[i].port, g_record_table.table[i].proto);

        for(j = i+1; j < g_record_table.items; j++){
            if(ip != g_record_table.table[j].src) continue;
            // Check is timeval too great
            timeval = get_timeval(start_time, &g_record_table.table[j].time);
            if(timeval == -1 || timeval > g_interval) break;
            if(!port_in_list(conn_table, g_record_table.table[j].port)){
                start_time = &g_record_table.table[j].time;
                add_portproto(conn_table, g_record_table.table[j].port, g_record_table.table[j].proto);
            }
        }
        if(conn_table->items >= g_cons){
            strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", &g_record_table.table[i].time);
            form_port_string(port_str, conn_table);

            if(g_csv_format){
                if(g_print_ports){
                    printf("%s,%s,\"%s\"\n", timestr, g_ip_table.table[g_record_table.table[i].src], port_str->buffer);
                }else{
                    printf("%s,%s,%s\n", timestr, g_ip_table.table[g_record_table.table[i].src], port_str->buffer);
                }
            }else{
                printf("%s %s %s\n", timestr, g_ip_table.table[g_record_table.table[i].src], port_str->buffer);
            }
        }
        i = j-1;
        // Reset
        conn_table->items = 0;
    }

    return 0;
}

int parse_log(FILE* fp){
     // File stream variables
    char* buffer = NULL;
    size_t len = 0;
    unsigned int line_num = 0;
    unsigned int readed;

    // Match variables
    const char* time_status;
    PayloadSubStr payload_result;

    // Parsing variables
    struct tm temp_time;
    IP temp_ip;
    Record temp_record;

    // Parse lines
    while((readed = getline(&buffer, &len, fp)) != -1){
        line_num++;

        // Parse time
        time_status = parse_time(buffer, "%b %d %H:%M:%S", &temp_time);
        if(time_status == NULL || time_status - buffer < 15){
            fprintf(stderr, "error: failed to parse time in line %i\n", line_num);
            continue;
        }
        // Skip if not the specified date
        if(g_date_type != -1 && date_equal(&temp_time) != 1) continue;

        // Find payload
        payload_result = find_payload(buffer, readed);
        if(payload_result.status == 0) continue;

        // Parse payload
        // Let's not use regex because it's slow
        if(parse_record(&temp_ip, &temp_record, buffer, &payload_result) != 0){
            fprintf(stderr, "error: invalid syntax in line %i\n", line_num);
            return 1;
        }
        temp_record.time = temp_time;
        // Assume the year to be current
        temp_record.time.tm_year = g_time_now.tm_year;

        add_iprecord(&temp_ip, &temp_record);
    }

    free(buffer);

    return 0;
}

int check_log(){
    FILE* fp = NULL;

    if(initialise_tables(2000, 5000) != 0){
        return 1;
    }

    if(g_read_stdin){
        fp = stdin;
        if(parse_log(fp) != 0){
            return 1;
        }
    }else{
        for(unsigned int i = 0; i < g_log_count; i++){
            fp = fopen(g_log_location[i], "r");

            // Open file
            if(fp == NULL && !g_read_stdin){
                fprintf(stderr, "error while opening file \"%s\"\n", g_log_location[i]);
                perror("error");
                return 1;
            }else if(fp == NULL){
                fprintf(stderr, "error: stdin points to NULL\ncannot read user input\n");
                return 1;
            }

            if(parse_log(fp) != 0){
                return 1;
            }
        }
    }

    fclose(fp);

    // Check variables
    ConnTable conn_table;
    PortStr port_str;


    // Csv header
    if(g_csv_format){
        printf("scan_time,address,ports\n");
    }

    // Initialise connection table and port_str
    conn_table.len = 50;
    conn_table.items = 0;
    conn_table.table = malloc(sizeof(PortProto) * conn_table.len);

    port_str.len = 100;
    port_str.chars = 0;
    port_str.buffer = malloc(sizeof(char) * port_str.len);

    // TODO add threads?
    // Find port scans

    for(unsigned int i = 0; i < g_ip_table.items; i++){
        check_ip(i, &conn_table, &port_str);
        conn_table.items = 0;
        port_str.chars = 0;
    }

    free(conn_table.table);
    free(port_str.buffer);

    deallocate_tables();

    return 0;
}

int files_accessible(){
    if(g_read_stdin) return 1;

    for(unsigned int i = 0; i < g_log_count; i++){
        if(access(g_log_location[i], R_OK) != 0){
            fprintf(stderr, "error: cannot access file \"%s\"\n", g_log_location[i]);
            return 0;
        }
    }
    return 1;
}

int main(int argc, char** argv){
    FILE* fp = NULL;

    // Initialise
    g_program_name = argv[0];
    // Use stack by default
    // If there is more than one file new memory is allocated to heap
    // It's not freed because there is no point in that
    // This will however show up as an error in valgrind
    const char* default_pointer[1] = { NULL };
    g_log_location = default_pointer;
    g_log_location[0] = NULL;

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

    if(g_log_location[0] == NULL){
        fprintf(stderr, "error: please define the log file location\n");
        print_help(NULL);
        return 1;
    }

    if(!files_accessible()){
        return 1;
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
