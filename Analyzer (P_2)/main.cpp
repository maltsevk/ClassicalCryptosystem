
#include "MyCryptoAnalyzer.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <map>

#define ANALYSIS_RESULT_PATH	"analysis_result.txt"
#define DECRYPTED_TEXT_PATH		"decrypted_text.txt"

int analyzeCryptoTrans(std::string & openedTextPath, std::string & cipherTextPath)
{
	std::string encryptedText;
	std::string openedTextPart;
	std::vector <int> key;
	int textSize, keySize;

	// reading cipher text from file
	textSize = readFile(cipherTextPath, encryptedText);
	if (textSize <= 0)
		return -1;

	// reading 1/3 opened text from file
	textSize = getOpenedTextPartFromFile(openedTextPath, openedTextPart);
	if (textSize <= 0)
		return -1;

	// search the key
	keySize = getKey(encryptedText, openedTextPart, key);
	if (keySize == 0)
		std::cout << "[ ERROR ] Can not find the key" << std::endl;
	else if (std::find(key.begin(), key.end(), -1) == key.end()) {
		// the key found and fully restored
		std::cout << "[ SUCCESS ] The key is fully restored " << showKey(key).c_str() << std::endl;
		writeTextToFile(decryptText(encryptedText, key), ANALYSIS_RESULT_PATH);
	}
	else {
		// the key found but unfully restored. Undefined key part
		// find via brute force (not more 10 variants)
		std::cout << "[ SUCCESS ] Part of the key could not be recovered." << std::endl;
		bruteForceKeyPart(encryptedText, openedTextPart, key, ANALYSIS_RESULT_PATH);
	}

	return 0;
}

int friedmanTests(std::string & freqAlphabetPath, std::string & vigenerCipherPath)
{
	std::string encryptedVigenerText;
	std::string decryptedVigenerText;
	std::map <char, double> freqAlphabet;
	std::vector <int> key;

	int res, keyLength;

	res = getAlphabetFromFile(freqAlphabetPath, freqAlphabet);
	if (res < 0)
		return -1;

	res = readFile(vigenerCipherPath, encryptedVigenerText);
	if (res <= 0)
		return -1;

	keyLength = firstFriedmanTest(encryptedVigenerText, freqAlphabet, key);
	key.resize(keyLength);

	// determination the first key element via frequency method
	key[0] = computeKeyElement(0, keyLength, encryptedVigenerText, freqAlphabet);

	// determination other key elements via friedman test
	secondFriedmanTest(encryptedVigenerText, freqAlphabet, key, keyLength);

	std::cout << "[ SUCCESS ] The key is fully restored via Friedman test two : " << showKey(key).c_str() << std::endl;

	decryptedVigenerText = decryptVigenerCipher(encryptedVigenerText, key, freqAlphabet);
	writeTextToFile(decryptedVigenerText, DECRYPTED_TEXT_PATH);

	return 0;
}


int main(int argc, char* argv[])
{
	int res;

	res = analyzeCryptoTrans(std::string(argv[2]), std::string(argv[3]));
	if (res < 0)
		return -1;

	res = friedmanTests(std::string(argv[1]), std::string(argv[4]));
	if (res < 0)
		return -1;

	return 0;
}