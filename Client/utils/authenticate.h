// Authenticate.h

#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H
#include <string>
#include "KeyStruct.h"



KEY authenticate(int sock, const std::string& username);

#endif // AUTHENTICATE_H
