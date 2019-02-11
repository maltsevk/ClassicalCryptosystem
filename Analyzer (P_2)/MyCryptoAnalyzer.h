#ifndef _MYCRYPTOANALYZER_H
#define _MYCRYPTOANALYZER_H

#include <vector>
#include <map>

#define SPECIAL_VALUE 0.065

// Functions for work with vertical permutation
size_t getKey(const std::string &, const std::string &, std::vector<int> &);
std::string decryptText(const std::string &, std::vector<int> &);
void bruteForceKeyPart(const std::string &, const std::string &, std::vector<int> &, const std::string &);
std::string showKey(std::vector<int> &);

// Functions for work with Friedmans tests
int firstFriedmanTest(const std::string &, std::map <char, double> &, std::vector <int> &);
int secondFriedmanTest(const std::string &, std::map <char, double> &, std::vector <int> &, size_t);
std::string decryptVigenerCipher(std::string &, std::vector<int> &, std::map<char, double> &);
int computeKeyElement(int, int, const std::string &, std::map <char, double> &);

// Functions for work with files
int readFile(const std::string &, std::string &);
int getAlphabetFromFile(const std::string &, std::map <char, double> &);
int getOpenedTextPartFromFile(const std::string &, std::string &);
void writeTextToFile(const std::string &, const std::string &);

#endif // _MYCRYPTOANALYZER_H