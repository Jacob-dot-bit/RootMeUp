/*
 * VAULT-9 :: Console d'administration
 * Challenge Red Team 3 (intermediaire) - RootMeUp
 *
 * Deux etapes :
 *   1. Reverse : contourner la verification de licence (obfusquee en XOR).
 *   2. Exploitation : debordement de tampon (ret2win) vers vault().
 *
 * secret.h est genere au build par setup/gen_secret.py : il contient
 * la licence encodee en XOR (jamais le texte en clair) afin que `strings`
 * sur le binaire distribue ne revele pas la solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "secret.h"   /* LICENSE_ENC[], LICENSE_LEN, XOR_KEY */

char flag1[128];
char flag2[128];

static void load_flag(const char *path, char *dst, size_t n)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { strncpy(dst, "FLAG_MANQUANT", n); dst[n - 1] = 0; return; }
    ssize_t r = read(fd, dst, n - 1);
    if (r < 0) r = 0;
    dst[r] = 0;
    char *nl = strchr(dst, '\n');
    if (nl) *nl = 0;
    close(fd);
}

static void setup(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    load_flag("/challenge/flag1.txt", flag1, sizeof(flag1));
    load_flag("/challenge/flag2.txt", flag2, sizeof(flag2));
}

/* Etape 2 : fonction "gagnante" jamais atteinte par le flux normal. */
void vault(void)
{
    puts("");
    puts("[+] Coffre deverrouille -- acces au module memoire protege accorde.");
    printf("[+] flag 2: %s\n", flag2);
    fflush(stdout);
    _exit(0);
}

/* Etape 1 : la licence attendue est stockee XORee avec XOR_KEY. */
static int check_license(const char *input)
{
    if (strlen(input) != LICENSE_LEN)
        return 0;
    for (size_t i = 0; i < LICENSE_LEN; i++) {
        if ((unsigned char)(input[i] ^ XOR_KEY) != LICENSE_ENC[i])
            return 0;
    }
    return 1;
}

/* Debordement volontaire : read() ecrit jusqu'a 200 octets dans buf[64]. */
static void access_terminal(void)
{
    char buf[64];
    puts("");
    puts("=== Terminal de maintenance ===");
    printf("Commande > ");
    read(0, buf, 200);
    printf("Commande '%s' non reconnue.\n", buf);
}

int main(void)
{
    setup();

    char license[128];
    puts("========================================");
    puts("   VAULT-9 :: Console d'administration   ");
    puts("========================================");
    printf("Cle de licence > ");
    if (!fgets(license, sizeof(license), stdin))
        return 0;
    license[strcspn(license, "\r\n")] = 0;

    if (check_license(license)) {
        puts("[+] Licence valide. Bienvenue, administrateur.");
        printf("[+] Preuve d'acces (flag 1): %s\n", flag1);
        access_terminal();
    } else {
        puts("[-] Licence invalide. Acces refuse.");
    }
    return 0;
}
