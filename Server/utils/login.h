// Login.h

#ifndef LOGIN_H
#define LOGIN_H
#include <string>
#include "KeyStruct.h"
using namespace std;


void Decrypt(int new_socket,unsigned char* digest, string uname,unsigned char** clear_buf_out, size_t* clear_size_out,size_t* aad1_out, size_t* aad2_out, size_t* aad3_out);
void Encrypt(int sock,unsigned char* digest, string uname,unsigned char* clear_buf_new, size_t clear_size_new,size_t aad1_new,size_t aad2_new,size_t aad3_new);

#endif // LOGIN