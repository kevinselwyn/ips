#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "ips.h"

static struct option options[] = {
    { "patch",  required_argument, 0, 'p' },
    { "output", required_argument, 0, 'o' },
    { "quiet",  no_argument,       0, 'q' },
    { "help",   no_argument,       0, 'h' },
    { 0,        0,                 0,  0  }
};

int usage(char *exec) {
    fprintf(stderr, "\nIPS patcher\n\n");
    fprintf(stderr, "Usage: %s [options] <infile>\n\n", exec);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "  -p, --patch <patchfile>  IPS patch file\n");
    fprintf(stderr, "  -o, --output <outfile>   Output\n");
    fprintf(stderr, "  -q, --quiet              Silence logging\n\n");

    fprintf(stderr, "  -h, --help               Print this help message\n\n");

    return 1;
}

int main(int argc, char *argv[]) {
    char *exec = argv[0];
    char *infile = NULL;
    char *patchfile = NULL;
    char *outfile = NULL;
    int opt = 0;
    int opt_index = 0;
    int rc = 0;
    ips_context *ips = NULL;

    ips = (ips_context *)malloc(sizeof(ips_context));

    if ((rc = ips_init(ips)) != 0) {
        goto cleanup;
    }

    while ((opt = getopt_long(argc, argv, "p:o:qh", options, &opt_index)) != -1) {
        switch (opt) {
        case 'p':
            patchfile = optarg;

            break;
        case 'o':
            outfile = optarg;

            break;
        case 'q':
            ips->quiet = 1;

            break;
        case 'h':
        case '?':
        default:
            rc = usage(exec);

            goto done;
        }
    }

    if (!patchfile) {
        fprintf(stderr, "%s: option '--patch' requires an argument\n", exec);

        rc = usage(exec);
        goto done;
    }

    if (!outfile) {
        fprintf(stderr, "%s: option '--output' requires an argument\n", exec);

        rc = usage(exec);
        goto done;
    }

    if (optind < argc) {
        infile = argv[optind];
    } else {
        fprintf(stderr, "%s: <infile> is required\n", exec);

        rc = usage(exec);
        goto done;
    }

    if ((rc = ips_open_input(ips, infile)) != 0) {
        goto cleanup;
    }

    if ((rc = ips_open_patch(ips, patchfile)) != 0) {
        goto cleanup;
    }

    while ((rc = ips_apply(ips)) < 0) {
        if (rc == 1) {
            goto cleanup;
        }
    }

    if ((rc = ips_save(ips, outfile)) != 0) {
        goto cleanup;
    }

cleanup:
    if ((rc = ips_close(ips)) != 0) {
        goto cleanup;
    }

done:
    return rc;
}
