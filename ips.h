#ifndef IPS_H
#define IPS_H

typedef struct ips_context {
    int quiet;
    char *filedata;
    size_t filesize;
    FILE *input;
    FILE *patch;
    FILE *output;
} ips_context;

typedef enum ips_loglevel {
    IPS_INFO,
    IPS_ERROR
} ips_loglevel;

void ips_log(ips_context *ips, ips_loglevel level, const char *fmt, ...);
int ips_init(ips_context *ips);
int ips_open_input(ips_context *ips, const char *filename);
int ips_open_patch(ips_context *ips, const char *filename);
int ips_apply(ips_context *ips);
int ips_save(ips_context *ips, const char *filename);
int ips_close(ips_context *ips);

#endif /* IPS_H */
