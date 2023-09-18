// upload.h

#ifndef UPLOAD_H
#define UPLOAD_H
#include <string>
using namespace std;

void client_upload(int sock,unsigned char* digest, string uname);

#endif // UPLOAD_H