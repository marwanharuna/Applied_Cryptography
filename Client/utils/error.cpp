#include "error.h"
#include <iostream>

int handleErrors(std::string data){
      std::cerr <<"\n An error occurred with: "<<data<<std::endl;
        exit(1);
    }