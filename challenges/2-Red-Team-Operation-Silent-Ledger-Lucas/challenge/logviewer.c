/*
 * Meridian Capital - Internal Log Viewer
 * Allows members of the "analysts" group to view sanitized application
 * logs without needing full root access.
 *
 * Usage: logviewer <lognam e>
 * Reads /var/log/meridian/<logname>.log
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <logname>\n", argv[0]);
        return 1;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cat /var/log/meridian/%s.log", argv[1]);

    /* Drop to root to be able to read protected log files */
    setuid(0);
    setgid(0);

    system(cmd);
    return 0;
}
