
#include "MyCryptoProvider.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <windows.h>

using namespace std;

int readOpenedTextFromFile(char* path, BYTE** buffer)
{
	ifstream file(path, ios_base::binary);
	if (!file.is_open()) {
		cout << "[ ERROR ] Can not open the file" << endl;
		return -1;
	}

	file.seekg(0, ios_base::end);
	int fileSize = (int)file.tellg();
	file.seekg(0, ios_base::beg);

	if (fileSize > 0) {
		*buffer = new BYTE[fileSize];
	}
	else {
		cout << "[ ERROR ] The file is empty" << endl;
		file.close();
		return -1;
	}

	file.read((char *)*buffer, fileSize);
	file.close();

	cout << "[ SUCCESS ] The data was read from " << path << endl;
	return fileSize;
}

void getAlphabet(BYTE* openText, int openedTextSize, std::map <char, double> & freqAlphabet)
{
	for (int i = 0; i < openedTextSize; i++) {
		auto findIter = freqAlphabet.find(openText[i]);
		if (findIter == freqAlphabet.end())
			freqAlphabet[openText[i]] = 1.0;
		else
			freqAlphabet[openText[i]] += 1.0;
	}

	for (auto iter = freqAlphabet.begin(); iter != freqAlphabet.end(); iter++)
		iter->second /= openedTextSize;

	cout << "[ SUCCESS ] The frequency alphabet is obtained. Alphabet capacity: " << freqAlphabet.size() << endl;
}

void writeFreqAlphabetToFile(std::map <char, double> & freqAlphabet, size_t openedTextSize, char* path)
{
	ofstream file(path, ios_base::binary);

	for (auto elem : freqAlphabet)
		file << elem.first << " " << elem.second << "\r\n";

	file.close();

	cout << "[ SUCCESS ] The frequencies was written to " << path << endl;
}

int findDivisor(int a)
{
	for (int i = 3; i < a; i++) {
		if (a % i == 0)
			return i;
	}

	return -1;
}

int generateKey(size_t textSize, size_t** key)
{
	int rowAmount, columnAmount;

	rowAmount = findDivisor(textSize);
	if (rowAmount < 0) {
		cout << "[ ERROR ] The number of characters in the text can not be a \
prime number. Complete the text with one character" << endl;
		return -1;
	}

	columnAmount = textSize / rowAmount;
	// make the key length the least of these numbers
	if (columnAmount > rowAmount) {
		size_t tmp = columnAmount;
		columnAmount = rowAmount;
		rowAmount = tmp;
	}

	*key = new size_t [columnAmount];

	// build sequence [1, columnAmount]
	for (int i = 0; i < columnAmount; i++) {
		(*key)[i] = i + 1;
	}

	srand((unsigned int)time(NULL));
	// change random positions columnAmount times 
	for (int i = 0; i < columnAmount; i++) {
		swap((*key)[(rand() % columnAmount)], (*key)[(rand() % columnAmount)]);
	}

	cout << "[ SUCCESS ] The key is generated [";
	for (int i = 0; i < columnAmount; i++) {
		cout << (*key)[i];
		if (i != columnAmount - 1)
			cout << ", ";
		else
			cout << "]" << endl;
	}

	return columnAmount;
}

BYTE* encryptVerticalPermutationCipher(BYTE* openedText, size_t textSize)
{
	size_t *key;

	int keySize = generateKey(textSize, &key);
	if (keySize < 0)
		return nullptr;

	int nRows = textSize / keySize;
	BYTE* cipherText = new BYTE[textSize];

	// vertical permutation
	for (int i = 0; i < nRows; i++) {
		for (int j = 0; j < keySize; j++) {
			cipherText[nRows * (key[j] - 1) + i] = openedText[keySize * i + j];
		}
	}

	cout << "[ SUCCESS ] The ciphertext is created via vertical permutation cipher" << endl;

	delete[] key;
	return cipherText;
}

BYTE* encryptVigenerCipher(BYTE* openText, size_t textSize, std::map <char, double> & freqAlphabet, vector <size_t> & key)
{
	BYTE* cipherText = new BYTE[textSize];
	std::string alphabet;

	for (auto elem : freqAlphabet) {
		alphabet += elem.first;
	}

	int i, j, k = 0;
	for (i = 0; i < (int)textSize; i++) {
		j = alphabet.find(openText[i]);
		j += key[k];
		j %= freqAlphabet.size();
		k = (k + 1) % key.size();

		cipherText[i] = alphabet[j];
	}

	cout << "[ SUCCESS ] The ciphertext is created via Vigener cipher" << endl;

	return cipherText;
}

void writeEncryptedTextToFile(BYTE* pEncryptedText, size_t textSize, char* path)
{
	ofstream file(path, ios_base::binary);
	file.write((char*)pEncryptedText, textSize);
	file.close();

	cout << "[ SUCCESS ] The encrypted text was written to " << path << endl;
}