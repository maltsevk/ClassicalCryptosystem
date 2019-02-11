#ifndef _MYCRYPTOPROVIDER_H
#define _MYCRYPTOPROVIDER_H

#include <windows.h>
#include <vector>
#include <map>

int readOpenedTextFromFile(char*, BYTE**);
void getAlphabet(BYTE*, int, std::map <char, double> &);
void writeFreqAlphabetToFile(std::map <char, double> &, size_t, char* );
BYTE* encryptVerticalPermutationCipher(BYTE*, size_t);
BYTE* encryptVigenerCipher(BYTE*, size_t, std::map <char, double> &, std::vector <size_t> &);
void writeEncryptedTextToFile(BYTE*, size_t, char*);

#endif // _MYCRYPTOPROVIDER_H