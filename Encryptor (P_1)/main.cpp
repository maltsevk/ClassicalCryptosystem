
#include "MyCryptoProvider.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <windows.h>

#define FREQ_ALPHABET_PATH		"freq_alphabet.txt"
#define VERT_PERM_CIPHER_PATH	"vertical_permutation_cipher.txt"
#define VIGENER_CIPHER_PATH		"vigener_cipher.txt"

using namespace std;

int main(int argc, char* argv[])
{
	BYTE* openedText = nullptr;
	BYTE* encryptedText = nullptr;
	std::map <char, double> freqAlphabet;
	vector <size_t> vigenerKey = { 14, 7, 18 };

	// reading opened text from file
	int textSize = readOpenedTextFromFile(argv[1], &openedText);
	if (textSize <= 0) {
		return -1;
	}

	// determine frequency alphabet
	getAlphabet(openedText, textSize, freqAlphabet);

	// writing frequency alphabet to the file
	writeFreqAlphabetToFile(freqAlphabet, textSize, FREQ_ALPHABET_PATH);

	// encrypt opened text by vertical permutation
	encryptedText = encryptVerticalPermutationCipher(openedText, textSize);
	if (encryptedText == nullptr) {
		delete[] openedText;
		return -1;
	}

	writeEncryptedTextToFile(encryptedText, textSize, VERT_PERM_CIPHER_PATH);

	delete[] encryptedText;

	// encrypt opened text by Vigenere cipher
	encryptedText = encryptVigenerCipher(openedText, textSize, freqAlphabet, vigenerKey);
	if (encryptedText == nullptr) {
		delete[] openedText;
		return -1;
	}

	writeEncryptedTextToFile(encryptedText, textSize, VIGENER_CIPHER_PATH);

	delete[] encryptedText;
	delete[] openedText;

	return 0;
}