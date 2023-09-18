// download.h

#ifndef DOWNLOAD_H
#define DOWNLOAD_H
#include <string>
#include "error.h"
using namespace std;

void cloud_download(int new_socket, unsigned char* digest, string uname);

#endif // DOWNLOAD_H