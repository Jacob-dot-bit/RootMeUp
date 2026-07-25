/*
 * Meridian Capital - Internal Log Viewer
 * Lets the "orch" group run log lookups on behalf of the svc_orch service
 * account, without handing out an interactive session on that account.
 *
 * Usage: logviewer <logname>
 * Reads /var/log/meridian/<logname>.log
 *
 * DESIGN NOTE (CTF): this binary is SUID *svc_orch* (NOT root). The
 * command-injection weakness below is intentional (flag 6), but it can only
 * ever yield svc_orch privileges -- never root -- which keeps the
 * privilege-escalation chain strictly monotonic (root is only reachable at
 * the very last system step, via the orchestrator).
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

    /*
     * Assume the file owner's identity fully (real + effective) so the spawned
     * command runs as svc_orch. We deliberately do NOT setuid(0): the binary
     * is owned by svc_orch, so geteuid()/getegid() are svc_orch here.
     */
    if (setregid(getegid(), getegid()) != 0) { /* best effort */ }
    if (setreuid(geteuid(), geteuid()) != 0) { /* best effort */ }

    system(cmd);
    return 0;
}
