#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include "ips.h"

#ifdef _OPENSSL

#include <openssl/md5.h>

#endif /* _OPENSSL */

void ips_log(ips_context *ips, ips_loglevel level, const char *fmt, ...) {
    if (ips->quiet == 1) {
        return;
    }

    char buffer[16];
    va_list args;
    time_t t = time(NULL);
    struct tm *lt = localtime(&t);

    memset(buffer, 0x00, sizeof(char) * 16);

    strftime(buffer, sizeof(buffer), "%H:%M:%S", lt);

    sprintf(buffer+8, " %s", level == IPS_INFO ? "INFO " : "ERROR");

    fprintf(stderr, "%s ", buffer);

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

int ips_init(ips_context *ips) {
    int rc = 0;

    memset(ips, 0x00, sizeof(ips_context));

    if (!(ips->filedata = (char *)malloc(sizeof(char) * 0x100FFFE))) {
        ips_log(ips, IPS_ERROR, "could not allocate memory");

        rc = 1;
        goto cleanup;
    }

cleanup:
    return rc;
}

int ips_open_input(ips_context *ips, const char *filename) {
    int rc = 0;

    if (!(ips->input = fopen(filename, "r"))) {
        ips_log(ips, IPS_ERROR, "could not open input file: %s", filename);

        rc = 1;
        goto cleanup;
    }

    if (fseek(ips->input, 0, SEEK_END) != 0) {
        rc = 1;
        goto cleanup;
    }

    ips->filesize = (size_t)ftell(ips->input);

    if (fseek(ips->input, 0, SEEK_SET) != 0) {
        rc = 1;
        goto cleanup;
    }

    if (fread(ips->filedata, sizeof(char), ips->filesize, ips->input) != ips->filesize) {
        ips_log(ips, IPS_ERROR, "could not read input file: %s", filename);

        rc = 1;
        goto cleanup;
    }

#ifdef _OPENSSL

    char hash[33];
    unsigned char result[MD5_DIGEST_LENGTH];
    int i = 0;
    int l = 0;

    MD5((const unsigned char *)ips->filedata, ips->filesize, result);

    memset(hash, 0x00, sizeof(char) * 33);

    for (i = 0, l = MD5_DIGEST_LENGTH; i < l; i++) {
        if (sprintf(hash+(i * 2), "%02x", result[i]) != 2) {
            ips_log(ips, IPS_ERROR, "could not create input hash");

            rc = 1;
            goto cleanup;
        }
    }

    ips_log(ips, IPS_INFO, "input hash: %s", hash);

#endif /* _OPENSSL */

cleanup:
    return rc;
}

int ips_open_patch(ips_context *ips, const char *filename) {
    int rc = 0;
    char header[6];

    if (!(ips->patch = fopen(filename, "r"))) {
        ips_log(ips, IPS_ERROR, "could not open patch file: %s", filename);

        rc = 1;
        goto cleanup;
    }

    memset(header, 0x00, sizeof(char) * 6);

    if ((fread(&header, sizeof(char), 5, ips->patch)) != 5) {
        ips_log(ips, IPS_ERROR, "could not read patch header: %s", filename);

        rc = 1;
        goto cleanup;
    }

    if (strcmp(header, "PATCH") != 0) {
        ips_log(ips, IPS_ERROR, "invalid patch file: %s", filename);

        rc = 1;
        goto cleanup;
    }

cleanup:
    return rc;
}

int ips_apply(ips_context *ips) {
    long int address = 0;
    size_t length = 0;
    char data[0xFFFF];
    int byte = 0;
    int rle = 0;
    int i = 0;
    int l = 0;
    int rc = -1;

    memset(data, 0x00, sizeof(char) * 0xFFFF);

    if (!ips->input) {
        ips_log(ips, IPS_ERROR, "missing file to patch");

        rc = 1;
        goto cleanup;
    }

    if (!ips->patch) {
        ips_log(ips, IPS_ERROR, "missing patch file");

        rc = 1;
        goto cleanup;
    }

    for (i = 0, l = 3; i < l; i++) {
        if (fread(&byte, sizeof(char), 1, ips->patch) != 1) {
            ips_log(ips, IPS_ERROR, "could not read patch file");

            rc = 1;
            goto cleanup;
        }

        address |= (byte & 0xFF) << ((l - i - 1) * 8);
    }

    if (address == 0x454F46) {
        rc = 0;
        goto cleanup;
    }

    for (i = 0, l = 2; i < l; i++) {
        if (fread(&byte, sizeof(char), 1, ips->patch) != 1) {
            ips_log(ips, IPS_ERROR, "could not read patch file");

            rc = 1;
            goto cleanup;
        }

        length |= (byte & 0xFF) << ((l - i - 1) * 8);
    }

    if (length == 0) {
        rle = 1;

        for (i = 0, l = 2; i < l; i++) {
            if (fread(&byte, sizeof(char), 1, ips->patch) != 1) {
                ips_log(ips, IPS_ERROR, "could not read patch file");

                rc = 1;
                goto cleanup;
            }

            length |= (byte & 0xFF) << ((l - i - 1) * 8);
        }

        if (fread(&byte, sizeof(char), 1, ips->patch) != 1) {
            ips_log(ips, IPS_ERROR, "could not read patch file");

            rc = 1;
            goto cleanup;
        }
    } else {
        rle = 0;

        if (fread(&data, sizeof(char), length, ips->patch) != length) {
            ips_log(ips, IPS_ERROR, "could not read patch file");

            rc = 1;
            goto cleanup;
        }
    }

    ips_log(ips, IPS_INFO, "applying patch: address=0x%06lx, length=0x%04x, rle=%d, data=[0x%02x%s", address, length, rle, rle == 0 ? data[0] : byte, rle == 0 ? ", ...]" : "]");

    if (rle == 0) {
        memcpy(ips->filedata+address, data, sizeof(char) * length);
    } else {
        memset(ips->filedata+address, byte, sizeof(char) * length);
    }

cleanup:
    return rc;
}

int ips_save(ips_context *ips, const char *filename) {
    int rc = 0;

    if (!(ips->output = fopen(filename, "w"))) {
        ips_log(ips, IPS_ERROR, "could not open output file: %s", filename);

        rc = 1;
        goto cleanup;
    }

    if (fwrite(ips->filedata, sizeof(char), ips->filesize, ips->output) != ips->filesize) {
        ips_log(ips, IPS_ERROR, "could not write output file: %s", filename);

        rc = 1;
        goto cleanup;
    }

#ifdef _OPENSSL

    char hash[33];
    unsigned char result[MD5_DIGEST_LENGTH];
    int i = 0;
    int l = 0;

    MD5((const unsigned char *)ips->filedata, ips->filesize, result);

    memset(hash, 0x00, sizeof(char) * 33);

    for (i = 0, l = MD5_DIGEST_LENGTH; i < l; i++) {
        if (sprintf(hash+(i * 2), "%02x", result[i]) != 2) {
            ips_log(ips, IPS_ERROR, "could not create output hash");

            rc = 1;
            goto cleanup;
        }
    }

    ips_log(ips, IPS_INFO, "output hash: %s", hash);

#endif /* _OPENSSL */

cleanup:
    return rc;
}

int ips_close(ips_context *ips) {
    int rc = 0;

    if (ips->input && ((rc = fclose(ips->input)) != 0)) {
        ips_log(ips, IPS_ERROR, "could not close input file");

        goto cleanup;
    }

    if (ips->patch && ((rc = fclose(ips->patch)) != 0)) {
        ips_log(ips, IPS_ERROR, "could not close patch file");

        goto cleanup;
    }

    if (ips->output && ((rc = fclose(ips->output)) != 0)) {
        ips_log(ips, IPS_ERROR, "could not close output file");

        goto cleanup;
    }

    free(ips->filedata);

cleanup:
    return rc;
}
