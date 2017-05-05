# rsx112crypt
Encryption command-line utility written in C. Supports RC4,  AES128-CBC and AES128-ECB

Assignment for the RSX112 course by Nicolas Pioch at [CNAM Paris](http://www.cnam-paris.fr)

The AES part is using [tiny-AES128-C library](https://github.com/kokke/tiny-AES128-C)

Usage: rsx112crypt [-h] [-D] [-s SKIPBYTES] -c {1-3} (1:rc4,2:aes-ecb,3:aes-cbc) -d [--decrypt] -k KEYFILE [--iv IV] -i INFILE -o OUTFILE

 Encrypt or decypt a file  

optional arguments:  
-h, --help show this  help message and exit.  
-D, --debug Enable debug diagnostics  
-s SKIPBYTES, --skipbytes SKIPBYTES  
Number of bytes to copy unmodified (default: 0)  
-c , --cipher 1(rc4), 2(aes-ecb), 3(aes-cbc) Cipher to use  
-k KEYFILE, --keyfile KEYFILE  Key file name  
--iv IV Initialization Vector file name (CBC only)  
-i INFILE, --infile INFILE Input file name  
-o OUTFILE, --outfile OUTFILE Output file name  

## Compilation

```bash
$ gcc -O3 -o rsx112crypt main.c aes.c
```