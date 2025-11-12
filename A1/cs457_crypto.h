#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <memory.h>

char* one_time_pad_encr();
char* one_time_pad_decr();
char* generate_key(int size);
char* affine_encr(char* plaintext);
char* affine_decr(char* ciphertext);
char* trithemius_encr(char* plaintext);
char* trithemius_decr(char* ciphertext);
char* scytale_encr(char* plaintext , int diameter);
char* scytale_decr(char* ciphertext , int diameter);
char* rail_fence_encr(char* plaintext , int rails);
char* rail_fence_decr(char* ciphertext , int rails);

