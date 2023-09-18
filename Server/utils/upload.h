// upload.h

#ifndef UPLOAD_H
#define UPLOAD_H
#include <string>
#include "error.h"
using namespace std;

void cloud_upload(int new_socket, unsigned char* digest, string uname);

#endif // UPLOAD_H