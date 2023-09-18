// upload.h

#ifndef DOWNLOAD_H
#define DOWNLOAD_H
#include <string>
using namespace std;

void client_download(int sock,unsigned char* digest, string uname, string file);

#endif // DOWNLOAD_H