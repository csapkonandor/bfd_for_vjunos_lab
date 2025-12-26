#include "bfd_session.h"
#include "bfd_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

extern int is_initiator;

int main(int argc, char **argv)
{
    is_initiator = 1;

    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s single|multi",
            argv[0]);
        return 1;
    }

    int mode = !strcmp(argv[1], "single") ?
        BFD_MODE_SINGLEHOP : BFD_MODE_MULTIHOP;

   
    bfd_engine_mode = mode;

    return bfd_engine_run(mode);
}
