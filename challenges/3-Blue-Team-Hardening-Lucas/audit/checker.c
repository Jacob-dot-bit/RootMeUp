/* ===========================================================================
 *  checker.c  -  Auto-évaluation de durcissement (NORTHWIND srv-legacy01)
 *  Blue Team CTF - Hardening - "Operation IRON GATE"
 *
 *  IMPORTANT : ce binaire n'affiche QUE la PROGRESSION (fait / à corriger).
 *  Il ne contient AUCUN flag. Les flags sont attribués côté serveur par le
 *  valideur `grader/grade.py` (hors de portée du joueur). Reverse-engineerer
 *  ce binaire ne révèle donc aucun secret : il n'y en a pas.
 *
 *  Variable d'env (test/admin) : AUDIT_ROOT = préfixe de chemin (defaut "").
 * =========================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char *ROOT = "";
static void mkpath(char *dst, size_t n, const char *p) { snprintf(dst, n, "%s%s", ROOT, p); }

static int path_mode(const char *p) {
    char b[512]; struct stat st; mkpath(b, sizeof b, p);
    if (stat(b, &st) != 0) return -1;
    return st.st_mode & 07777;
}
static int path_exists(const char *p) {
    char b[512]; struct stat st; mkpath(b, sizeof b, p);
    return stat(b, &st) == 0;
}
static int has_directive(const char *p, const char *key, const char *val) {
    char b[512]; mkpath(b, sizeof b, p);
    FILE *f = fopen(b, "r"); if (!f) return 0;
    char line[1024]; int found = 0;
    while (fgets(line, sizeof line, f)) {
        char *s = line; while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == 0) continue;
        char tmp[1024]; strncpy(tmp, s, sizeof tmp - 1); tmp[sizeof tmp - 1] = 0;
        char *k = strtok(tmp, " \t\r\n"); if (!k) continue;
        char *v = strtok(NULL, " \t\r\n");
        if (v && strcmp(k, key) == 0 && strcmp(v, val) == 0) { found = 1; break; }
    }
    fclose(f); return found;
}
static int has_active_token(const char *p, const char *token) {
    char b[512]; mkpath(b, sizeof b, p);
    FILE *f = fopen(b, "r"); if (!f) return 0;
    char line[1024]; int found = 0;
    while (fgets(line, sizeof line, f)) {
        char *s = line; while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == 0) continue;
        char tmp[1024]; strncpy(tmp, s, sizeof tmp - 1); tmp[sizeof tmp - 1] = 0;
        char *k = strtok(tmp, " \t\r\n");
        if (k && strcmp(k, token) == 0) { found = 1; break; }
    }
    fclose(f); return found;
}
static int has_rogue_uid0(const char *p) {
    char b[512]; mkpath(b, sizeof b, p);
    FILE *f = fopen(b, "r"); if (!f) return 0;
    char line[1024]; int found = 0;
    while (fgets(line, sizeof line, f)) {
        char tmp[1024]; strncpy(tmp, line, sizeof tmp - 1); tmp[sizeof tmp - 1] = 0;
        char *name = strtok(tmp, ":"); if (!name) continue;
        strtok(NULL, ":");
        char *uid = strtok(NULL, ":");
        if (uid && strcmp(uid, "0") == 0 && strcmp(name, "root") != 0) { found = 1; break; }
    }
    fclose(f); return found;
}
static int file_contains(const char *p, const char *needle) {
    char b[512]; mkpath(b, sizeof b, p);
    FILE *f = fopen(b, "r"); if (!f) return 0;
    char line[2048]; int found = 0;
    while (fgets(line, sizeof line, f)) if (strstr(line, needle)) { found = 1; break; }
    fclose(f); return found;
}

#define G "\033[32m"
#define R "\033[31m"
#define C "\033[36m"
#define D "\033[2m"
#define Y "\033[33m"
#define Z "\033[0m"

static int pass = 0;
static void ok(const char *label, const char *diff) {
    pass++;
    printf("  " G "[OK]" Z "  %-38s " D "%s" Z "\n", label, diff);
}
static void todo(const char *label, const char *diff, const char *hint) {
    printf("  " R "[À CORRIGER]" Z " %-31s " C "%-11s" Z " " D "%s" Z "\n", label, diff, hint);
}

int main(void) {
    const char *r = getenv("AUDIT_ROOT"); if (r) ROOT = r;
    int m;

    printf("\n  ================================================================\n");
    printf("   AUTO-ÉVALUATION DU DURCISSEMENT - srv-legacy01 (NORTHWIND)\n");
    printf("   Niveaux classés du plus FACILE au plus DIFFICILE.\n");
    printf("   Plus tu avances, moins tu as d'indices.\n");
    printf("  ================================================================\n");

    /* ---- FACILE ---- */
    if (has_directive("/etc/ssh/sshd_config", "PermitRootLogin", "no")
        && !has_directive("/etc/ssh/sshd_config", "PermitRootLogin", "yes"))
        ok("1. SSH root login désactivé", "(facile)");
    else todo("1. SSH root login", "(facile)", "sshd_config : PermitRootLogin doit être 'no'");

    if (has_directive("/etc/ssh/sshd_config", "PermitEmptyPasswords", "no")
        && !has_directive("/etc/ssh/sshd_config", "PermitEmptyPasswords", "yes"))
        ok("2. Mots de passe vides refusés", "(facile)");
    else todo("2. PermitEmptyPasswords", "(facile)", "sshd_config : PermitEmptyPasswords doit être 'no'");

    m = path_mode("/etc/shadow");
    if (m >= 0 && (m & 007) == 0) ok("3. /etc/shadow protégé", "(facile)");
    else todo("3. Permissions /etc/shadow", "(facile)", "ne doit pas être lisible par 'other' (ex: chmod 640)");

    /* ---- MOYEN ---- */
    m = path_mode("/opt/app/.env");
    if (m >= 0 && (m & 077) == 0) ok("4. Secret applicatif protégé", "(moyen)");
    else todo("4. Secret en clair", "(moyen)", "un secret applicatif est lisible par tout le monde");

    if (!path_exists("/etc/cron.d/sysupdate")) ok("5. Persistance planifiée purgée", "(moyen)");
    else todo("5. Persistance planifiée", "(moyen)", "une tâche planifiée effectue un rappel réseau suspect");

    if (!has_active_token("/etc/inetd.conf", "telnet")) ok("6. Service en clair désactivé", "(moyen)");
    else todo("6. Service réseau", "(moyen)", "un service réseau en clair écoute encore");

    /* ---- DIFFICILE ---- */
    if (!has_rogue_uid0("/etc/passwd")) ok("7. Aucun accès admin caché", "(difficile)");
    else todo("7. Comptes utilisateurs", "(difficile)", "un accès administrateur illégitime subsiste");

    m = path_mode("/usr/local/bin/oldbackup");
    if (m < 0 || (m & 04000) == 0) ok("8. Élévation de privilèges corrigée", "(difficile)");
    else todo("8. Droits d'exécution", "(difficile)", "un binaire permet une élévation de privilèges");

    /* ---- EXPERT (aucun indice) ---- */
    m = path_mode("/usr/local/bin");
    if (m >= 0 && (m & 002) == 0) ok("9. Intégrité du PATH", "(expert)");
    else todo("9. Intégrité du PATH", "(expert)", "-");

    if (!path_exists("/root/.ssh/authorized_keys")
        || !file_contains("/root/.ssh/authorized_keys", "ctf-attacker"))
        ok("10. Accès distant résiduel", "(expert)");
    else todo("10. Accès distant résiduel", "(expert)", "-");

    printf("  ----------------------------------------------------------------\n");
    printf("   Progression : " Y "%d/10" Z " correctifs appliqués\n", pass);
    printf("  ================================================================\n");
    printf("   Pour chaque contrôle en [OK], récupère ton flag avec :\n");
    printf("       " G "getflag <numéro>" Z "   (ex: getflag 1)\n");
    printf("   Le flag est validé côté serveur puis à saisir dans CTFd.\n");
    printf("   (Aucun flag n'est stocké sur cette machine.)\n\n");
    return 0;
}
