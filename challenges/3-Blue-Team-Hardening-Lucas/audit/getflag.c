/* ===========================================================================
 *  getflag.c  -  Délivre le flag d'une tâche SI elle est réellement durcie.
 *  Blue Team CTF - Hardening - "Operation IRON GATE"  (server-less)
 *
 *  Usage : getflag <N>   (N de 1 à 10)
 *
 *  Les flags sont stockés XOR-obfusqués (aucun flag en clair dans l'image :
 *  `strings` ne renvoie rien). Un flag n'est décodé et affiché QUE si le
 *  contrôle correspondant passe. Binaire compilé avec symboles supprimés.
 *
 *  Limite assumée : le joueur étant root sur son instance, un reverse
 *  engineering déterminé reste possible — inhérent à toute solution sans
 *  composant serveur. Objectif ici : bloquer la triche « facile » (cat/strings)
 *  et exiger le vrai durcissement.
 *
 *  AUDIT_ROOT (env) : préfixe de chemin pour les tests.
 * =========================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define KEY 0x5A

/* flags XOR-obfusqués (clé 0x5A, terminateur inclus) */
static const unsigned char F01[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x28,0x6a,0x6a,0x2e,0x05,0x36,0x6a,0x3d,0x33,0x34,0x05,0x3e,0x33,0x29,0x3b,0x38,0x36,0x3f,0x3e,0x27,0x5a};
static const unsigned char F02[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x34,0x6a,0x05,0x3f,0x37,0x2a,0x2e,0x23,0x05,0x2a,0x3b,0x29,0x29,0x2d,0x6a,0x28,0x3e,0x29,0x27,0x5a};
static const unsigned char F03[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x29,0x32,0x3b,0x3e,0x35,0x2d,0x05,0x36,0x6a,0x39,0x31,0x3f,0x3e,0x05,0x3e,0x35,0x2d,0x34,0x27,0x5a};
static const unsigned char F04[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x29,0x3f,0x39,0x28,0x3f,0x2e,0x29,0x05,0x2a,0x3f,0x28,0x37,0x29,0x05,0x6c,0x6a,0x6a,0x27,0x5a};
static const unsigned char F05[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x37,0x3b,0x36,0x33,0x39,0x33,0x35,0x2f,0x29,0x05,0x39,0x28,0x35,0x34,0x05,0x2a,0x2f,0x28,0x3d,0x3f,0x3e,0x27,0x5a};
static const unsigned char F06[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x2e,0x3f,0x36,0x34,0x3f,0x2e,0x05,0x33,0x29,0x05,0x3e,0x3f,0x3b,0x3e,0x27,0x5a};
static const unsigned char F07[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x34,0x35,0x05,0x32,0x33,0x3e,0x3e,0x3f,0x34,0x05,0x28,0x6a,0x6a,0x2e,0x05,0x2f,0x29,0x3f,0x28,0x27,0x5a};
static const unsigned char F08[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x29,0x2f,0x33,0x3e,0x05,0x38,0x3b,0x39,0x31,0x3e,0x35,0x35,0x28,0x05,0x39,0x36,0x3f,0x3b,0x28,0x3f,0x3e,0x27,0x5a};
static const unsigned char F09[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x2d,0x28,0x33,0x2e,0x3b,0x38,0x36,0x3f,0x05,0x2a,0x3b,0x2e,0x32,0x05,0x29,0x3f,0x39,0x2f,0x28,0x3f,0x3e,0x27,0x5a};
static const unsigned char F10[] = {0x08,0x35,0x35,0x2e,0x17,0x3f,0x0f,0x2a,0x21,0x29,0x29,0x32,0x05,0x38,0x3b,0x39,0x31,0x3e,0x35,0x35,0x28,0x05,0x31,0x3f,0x23,0x05,0x28,0x3f,0x37,0x35,0x2c,0x3f,0x3e,0x27,0x5a};

static const unsigned char *FLAGS[] = {0,F01,F02,F03,F04,F05,F06,F07,F08,F09,F10};
static const int FLEN[] = {0,sizeof F01,sizeof F02,sizeof F03,sizeof F04,sizeof F05,
                           sizeof F06,sizeof F07,sizeof F08,sizeof F09,sizeof F10};

static char fbuf[128];
static const char *decode(int n) {
    const unsigned char *a = FLAGS[n]; int len = FLEN[n], i;
    for (i = 0; i < len; i++) fbuf[i] = (char)(a[i] ^ KEY);
    fbuf[len - 1] = 0; return fbuf;
}

/* --- lecture d'état (mêmes contrôles que l'audit) ------------------------- */
static const char *ROOT = "";
static void mkpath(char *d, size_t n, const char *p){ snprintf(d,n,"%s%s",ROOT,p); }

static int path_mode(const char *p){ char b[512]; struct stat st; mkpath(b,sizeof b,p);
    return stat(b,&st)?-1:(int)(st.st_mode&07777); }
static int path_exists(const char *p){ char b[512]; struct stat st; mkpath(b,sizeof b,p);
    return stat(b,&st)==0; }
static int has_directive(const char *p,const char *k,const char *v){ char b[512]; mkpath(b,sizeof b,p);
    FILE *f=fopen(b,"r"); if(!f) return 0; char line[1024]; int found=0;
    while(fgets(line,sizeof line,f)){ char *s=line; while(*s==' '||*s=='\t')s++;
        if(*s=='#'||*s=='\n'||!*s) continue; char t[1024]; strncpy(t,s,sizeof t-1); t[sizeof t-1]=0;
        char *kk=strtok(t," \t\r\n"); if(!kk)continue; char *vv=strtok(NULL," \t\r\n");
        if(vv&&!strcmp(kk,k)&&!strcmp(vv,v)){found=1;break;} } fclose(f); return found; }
static int has_active_token(const char *p,const char *tok){ char b[512]; mkpath(b,sizeof b,p);
    FILE *f=fopen(b,"r"); if(!f) return 0; char line[1024]; int found=0;
    while(fgets(line,sizeof line,f)){ char *s=line; while(*s==' '||*s=='\t')s++;
        if(*s=='#'||*s=='\n'||!*s) continue; char t[1024]; strncpy(t,s,sizeof t-1); t[sizeof t-1]=0;
        char *kk=strtok(t," \t\r\n"); if(kk&&!strcmp(kk,tok)){found=1;break;} } fclose(f); return found; }
static int has_rogue_uid0(const char *p){ char b[512]; mkpath(b,sizeof b,p);
    FILE *f=fopen(b,"r"); if(!f) return 0; char line[1024]; int found=0;
    while(fgets(line,sizeof line,f)){ char t[1024]; strncpy(t,line,sizeof t-1); t[sizeof t-1]=0;
        char *name=strtok(t,":"); if(!name)continue; strtok(NULL,":"); char *uid=strtok(NULL,":");
        if(uid&&!strcmp(uid,"0")&&strcmp(name,"root")){found=1;break;} } fclose(f); return found; }
static int file_contains(const char *p,const char *needle){ char b[512]; mkpath(b,sizeof b,p);
    FILE *f=fopen(b,"r"); if(!f) return 0; char line[2048]; int found=0;
    while(fgets(line,sizeof line,f)) if(strstr(line,needle)){found=1;break;} fclose(f); return found; }

/* renvoie 1 si la tâche N est réellement durcie */
static int hardened(int n){
    int m;
    switch(n){
    case 1: return has_directive("/etc/ssh/sshd_config","PermitRootLogin","no")
                && !has_directive("/etc/ssh/sshd_config","PermitRootLogin","yes");
    case 2: return has_directive("/etc/ssh/sshd_config","PermitEmptyPasswords","no")
                && !has_directive("/etc/ssh/sshd_config","PermitEmptyPasswords","yes");
    case 3: m=path_mode("/etc/shadow"); return m>=0 && (m&007)==0;
    case 4: m=path_mode("/opt/app/.env"); return m>=0 && (m&077)==0;
    case 5: return !path_exists("/etc/cron.d/sysupdate");
    case 6: return !has_active_token("/etc/inetd.conf","telnet");
    case 7: return !has_rogue_uid0("/etc/passwd");
    case 8: m=path_mode("/usr/local/bin/oldbackup"); return m<0 || (m&04000)==0;
    case 9: m=path_mode("/usr/local/bin"); return m>=0 && (m&002)==0;
    case 10: return !path_exists("/root/.ssh/authorized_keys")
                 || !file_contains("/root/.ssh/authorized_keys","ctf-attacker");
    }
    return 0;
}

int main(int argc, char **argv){
    const char *r=getenv("AUDIT_ROOT"); if(r) ROOT=r;
    if(argc<2){ printf("Usage : getflag <numero de 1 a 10>\n"); return 1; }
    int n=atoi(argv[1]);
    if(n<1||n>10){ printf("Numero invalide (1 a 10).\n"); return 1; }
    if(hardened(n)){
        printf("\033[32m[OK]\033[0m Tache %d validee !\n", n);
        printf("     Flag : \033[32m%s\033[0m\n", decode(n));
        printf("     -> a soumettre dans CTFd\n");
        return 0;
    }
    printf("\033[31m[KO]\033[0m Tache %d : pas encore corrigee.\n", n);
    printf("     Corrige la faille (voir 'audit') puis relance getflag %d.\n", n);
    return 2;
}
