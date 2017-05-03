#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <memory.h>
#include "aes.h"

int opt = 0, offset = 0, debug_mode = 0, decrypt = 0, cipher = 1;
long filesize;
const uint8_t *key, *iv;

uint8_t *entree, *sortie;

uint8_t *readfile(const uint8_t *f) {
    uint8_t *buffer = NULL;
    FILE *fp = fopen((const char *) f, "r");
    if (fp != NULL) {
        /* Go to the end of the file. */
        if (fseek(fp, 0L, SEEK_END) == 0) {
            /* Get the size of the file. */
            long bufsize = ftell(fp);
            if (bufsize == -1) {
                perror("Cannot get file length");
            }

            /* Allocate our buffer to that size. */
            buffer = malloc(sizeof(uint8_t) * (bufsize + 1));
            filesize = bufsize;

            /* Go back to the start of the file. */
            if (fseek(fp, 0L, SEEK_SET) != 0) {
                perror("Cannot read file");
            }

            /* Read the entire file into memory. */
            fread(buffer, sizeof(uint8_t), (size_t) bufsize, fp);
            if ( ferror( fp ) != 0 ) {
                fputs("Error reading file", stderr);
            }
        }
        fclose(fp);
    } else {
        perror("Impossible d'ouvrir le fichier");
        exit(1);
    }
    return buffer;
}

void writefile(const uint8_t *f, const uint8_t *b)  {
    FILE *fo = fopen((const char *) f, "w+b");
    fwrite(b, sizeof(uint8_t), (size_t) filesize, fo);
    if (debug_mode == 1) {
        printf("\n%zu octets écrits dans le fichier de sortie\n", filesize);
    }
    fclose(fo);
}

void print_usage() {
    printf("usage: rsx112crypt [-h] [-D] [-s SKIPBYTES] -c {1-3} (1:rc4,2:aes-ecb,3:aes-cbc) -d [--decrypt] -k KEYFILE [--iv IV] -i INFILE -o OUTFILE\n\n "
                   "Encrypt or decypt a file\n\n"
                   "optional arguments:\n"
                   "-h, --help show this help message and exit\n"
                   "-D, --debug Enable debug diagnostics\n"
                   "-s SKIPBYTES, --skipbytes SKIPBYTES\n"
                   "Number of bytes to copy unmodified (default: 0)\n"
                   "-c , --cipher 1(rc4), 2(aes-ecb), 3(aes-cbc)\n"
                   "Cipher to use\n"
                   "        -k KEYFILE, --keyfile KEYFILE\n"
                   "                              Key file name\n"
                   "--iv IV Initialization Vector file name (CBC only) "
                   "         -i INFILE, --infile INFILE\n"
                   "                              Input file name\n"
                   "         -o OUTFILE, --outfile OUTFILE\n"
                   "                              Output file name\n");
}

void bail() {
    print_usage();
    exit(EXIT_FAILURE);
}

void rc4(const uint8_t *keyfile, const uint8_t *inputfile, const uint8_t *outputfile)  {
    if (inputfile == NULL || outputfile == NULL)  {
        bail();
    }
    int i, j = 0;
    // Initialisation du tableau
    key = readfile(keyfile);
    if (debug_mode == 1) {
        printf("Longueur de clé: %zu octets (%ld bits)\n\n", filesize, filesize * 8);
    }
    int s[256], k[256], t[256];
    for (i = 0; i < 256; i++) {
        s[i] = i;
        k[i] = key[i % filesize];
    }

     for (i = 0; i < 256; i++) {
         j = (j + s[i] + k[i]) & 0xFF;
         t[i] = s[j];
         s[j] = s[i];
         s[i] = t[i];
         if (debug_mode == 1) {
             printf("%d ", s[i]);
         }
     }

    // Génération du flot de clé et chiffrement du buffer
    entree = readfile(inputfile);
    i = 0;
    j = 0;
    int c = 0;
    uint8_t K;
    sortie = malloc((size_t) filesize);
    while(filesize > 0)  {
        i = (i + 1) & 0xFF;
        j = (j + s[i]) & 0xFF;
        t[i] = s[j];
        s[j] = s[i];
        s[i] = t[i];
        K = (uint8_t) s[(s[i] + s[j]) & 0xFF];
        if (c < offset)  {
            sortie[c] = entree[c];
        } else {
            sortie[c] = entree[c] ^ K;
        }
        c++;
        filesize--;
    }

    free(entree);

    filesize = c;
    if (debug_mode == 1) {
        printf("\n\nIterations: %d Taille du buffer de sortie: %zu\n", c, filesize);
    }
    writefile(outputfile, sortie);
    free(sortie);
}

void aes128_ebc(const uint8_t *keyfile, const uint8_t *inputfile, const uint8_t *outputfile, int decrypt) {

    key = readfile(keyfile);
    if (debug_mode == 1) {
        printf("Longueur de clé: %zu octets (%ld bits)\n\n", filesize, filesize * 8);
    }

    entree = readfile(inputfile);
    sortie = malloc((size_t) filesize);
    if (debug_mode == 1) {
        printf("Taille du buffer d'entrée et de sortie: %ld\n", filesize);
    }

    long offsetsize = filesize - offset;

    if (offsetsize % 16 > 0) {
        long newsize = offsetsize + 16 - (offsetsize % 16);
        if (debug_mode == 1) {
            printf("Taille initiale %ld étendue à %ld\n", offsetsize, newsize);
        }
        uint8_t *newentree = realloc(entree, (size_t) newsize);
        uint8_t *newSortie = realloc(sortie, (size_t) newsize);
        offsetsize = newsize;
        entree = newentree;
        sortie = newSortie;
    }

    uint8_t bufEntree[16];
    uint8_t bufSortie[16];

    for (int i = 0; i < offsetsize; i += 16)  {
        memcpy(bufEntree, entree + offset + i, 16);
        // bufEntree = entree + i;
        if (decrypt == 0) {
            AES128_ECB_encrypt(bufEntree, key, bufSortie);
        } else {
            AES128_ECB_decrypt(bufEntree, key, bufSortie);
        }
        memcpy(sortie + offset + i, bufSortie, 16);
        if (debug_mode == 1)
            printf("16 octets écrits dans le buffer de sortie à l'adresse %p, total de %d octets\n", (void *) sortie + i, i + 16);
    }
    memcpy(sortie, entree, offset);
    writefile(outputfile, sortie);
    free(entree);
    free(sortie);
}


void aes128_cbc(uint8_t *keyfile, uint8_t *initvector, uint8_t *inputfile, uint8_t *outputfile, int decrypt) {
    key = readfile(keyfile);
    if (debug_mode == 1) {
        printf("Longueur de clé: %zu octets (%ld bits)\n\n", filesize, filesize * 8);
    }

    iv = readfile(initvector);
    if (debug_mode == 1) {
        printf("Longueur de l'IV: %zu octets (%ld bits)\n\n", filesize, filesize * 8);
    }

    entree = readfile(inputfile);
    sortie = malloc((size_t) filesize);
    if (debug_mode == 1) {
        printf("Taille du buffer d'entrée et de sortie: %ld\n", filesize);
    }

    long offsetsize = filesize - offset;
    if (decrypt == 0)  {
        AES128_CBC_encrypt_buffer(sortie + offset, entree + offset, (uint32_t)offsetsize, key, iv);
    } else {
        AES128_CBC_decrypt_buffer(sortie + offset, entree + offset, (uint32_t)offsetsize, key, iv);
    }
    memcpy(sortie, entree, offset);
    writefile(outputfile, sortie);
    free(entree);
    free(sortie);
}

int main(int argc, char *argv[]) {

    uint8_t *keyfile, *initvector, *infile, *outfile;
    keyfile = NULL;
    initvector = NULL;
    infile = NULL;
    outfile = NULL;

    static struct option long_options[] = {
            {"help",        no_argument,       0,  'h' },
            {"debug",       no_argument,       0,  'D' },
            {"decrypt",       no_argument,       0,  'd' },
            {"skipbytes",   required_argument, 0,  's' },
            {"cipher",      required_argument, 0,  'c' },
            {"keyfile",     required_argument, 0,  'k' },
            {"iv", required_argument, 0,  'I'},
            {"infile",      required_argument, 0,  'i' },
            {"outfile",     required_argument, 0,  'o' },
            {0,             0,                 0,  0   }
    };
    int long_index = 0;
    while ((opt = getopt_long(argc, argv,"hDds:c:k:I:i:o:",
                              long_options, &long_index )) != -1) {
        switch (opt) {
            case 'h' : print_usage();
                break;
            case 'D' : debug_mode = 1;
                break;
            case 'd' : decrypt = 1;
                break;
            case 's' : offset = atoi(optarg);
                break;
            case 'c' : cipher = atoi(optarg);
                break;
            case 'k' : keyfile = (uint8_t*) optarg;
                break;
            case 'I' : initvector = (uint8_t*) optarg;
                break;
            case 'i' : infile = (uint8_t*) optarg;
                break;
            case 'o' : outfile = (uint8_t*)optarg;
                break;
            default: bail();
        }
    }
    switch(cipher) {
        case 1: rc4(keyfile, infile, outfile);
            break;
        case 2: aes128_ebc(keyfile, infile, outfile, decrypt);
            break;
        case 3: aes128_cbc(keyfile, initvector, infile, outfile, decrypt);
            break;
        default: printf("Chiffrement inconnu\n");
            exit(1);
    }
    return 0;
}
