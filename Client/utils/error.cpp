#include "error.h"
#include <iostream>

int handleErrors(std::string data){
      std::cerr <<"\n An error occurred with: "<<data<<std::endl;
        exit(1);
    }

    bool isInputValid(const std::string& input) {
    for (char c : input) {
        // Check if the character is a letter (lowercase or uppercase),
        // a digit (0-9), or a period (".")
        if (!(std::isalpha(c) || std::isdigit(c) || c == '.')) {
            return false; // Invalid character found
        }
    }
    return true; // Input is valid
}