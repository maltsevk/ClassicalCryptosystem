
#include "MyCryptoAnalyzer.h"

#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <map>
#include <set>

int readFile(const std::string & path, std::string & buffer)
{
	std::ifstream file(path, std::ios::binary);

	if (!file.is_open()) {
		std::cout << "[ ERROR ] Can not open the file" << std::endl;
		return -1;
	}

	buffer = std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	if (buffer.size() == 0) {
		std::cout << "[ ERROR ] The file is empty" << std::endl;
		return -1;
	}

	std::cout << "[ SUCCESS ] The data was read from " << path.c_str() << std::endl;
	return buffer.size();
}

int getAlphabetFromFile(const std::string & path, std::map <char, double> & freqAlphabet)
{
	std::string buffer;
	char freq[12];
	char symbol;
	size_t j = 0, i = 0;

	int fileSize = readFile(path, buffer);
	if (fileSize <= 0)
		return -1;

	while (i < buffer.size()) {
		symbol = buffer[i];

		i++; // skip space
		j = 0;
		while (buffer[i] != '\r')
			freq[j++] = buffer[i++];

		i += 2; // skip /r and /n
		freqAlphabet[symbol] = atof(freq);
	}

	return 0;
}

int getOpenedTextPartFromFile(const std::string & path, std::string & openedTextPart)
{
	std::string str;

	int filesize = readFile(path, str);
	if (filesize <= 0)
		return -1;

	openedTextPart = str.substr(0, str.size() / 3);

	return filesize;
}

bool compareStrings(const std::string & str, const std::string & openedTextPart)
{
	size_t j;

	for (size_t i = 0; i < str.size(); i++)
	{
		// search symbols of the first string in the second
		j = openedTextPart.find(str[i]);
		if (j == std::string::npos)
			return false;

		// search symbols of the second string in the first
		j = str.find(openedTextPart[i]);
		if (j == std::string::npos)
			return false;
	}

	return true;
}

size_t getKey(const std::string & cipherText, const std::string & openedTextPart, std::vector<int> & key)
{
	std::string str;
	size_t nRows, nColumns;
	bool isWrongKeyLength;

	// brute force different table size
	for (nRows = 3; nRows < cipherText.size() / 2; nRows++) {

		if (cipherText.size() % nRows != 0)
			continue;

		nColumns = cipherText.size() / nRows;
		key.resize(nColumns, -1);
		isWrongKeyLength = false;

		for (size_t rowIndex = 0; rowIndex < (openedTextPart.size() / nColumns); rowIndex++) {
			// build row of cipher text from the table
			str.clear();
			for (size_t i = rowIndex; i < cipherText.size(); i += nRows)
				str += cipherText[i];

			// check: rows of the table contain the same symbols and amount of them
			// if does not then table size is not correct
			if (!compareStrings(str, openedTextPart.substr(rowIndex * nColumns, str.size()))) {
				isWrongKeyLength = true;
				break;
			}

			for (size_t i = 0; i < nColumns; i++) {
				size_t j = str.find(openedTextPart[rowIndex * nColumns + i], 0);
				size_t k = str.find(openedTextPart[rowIndex * nColumns + i], j + 1);

				if (k == std::string::npos && key[i] == -1)
					key[i] = j + 1;
				else if (k == std::string::npos && key[i] != -1 && key[i] != j + 1) {
					isWrongKeyLength = true;
					break;
				}
			}

			if (isWrongKeyLength == true || std::find(key.begin(), key.end(), -1) == key.end())
				break;
		}

		if (isWrongKeyLength == false)
			break;
	}

	return key.size();
}

std::string decryptText(const std::string & cipherText, std::vector<int> & key)
{
	std::string decryptedText = "";

	size_t nRows = cipherText.size() / key.size();
	size_t nColumns = key.size();

	for (size_t i = 0; i < nRows; i++)
		for (size_t j = 0; j < nColumns; j++)
			decryptedText += cipherText[(key[j] - 1) * nRows + i];

	return decryptedText;
}

std::string showKey(std::vector<int> & key)
{
	std::string str = "[";

	for (size_t i = 0; i < key.size(); i++) {
		str += std::to_string(key[i]);
		if (i != key.size() - 1)
			str += ", ";
	}
	str += "]";

	return str;
}

std::vector<int> getMissingNumbers(std::vector<int> & key)
{
	std::vector<int> missingNumbers(key.size());

	for (size_t i = 0; i < key.size(); i++)
		missingNumbers[i] = i + 1;

	for (size_t i = 0; i < key.size(); i++) {
		if (key[i] != -1) {
			auto it = std::find(missingNumbers.begin(), missingNumbers.end(), key[i]);
			missingNumbers.erase(it);
		}
	}

	return missingNumbers;
}

std::vector<int> getFilledRandomKey(std::vector<int> & key)
{
	std::vector<int> filledKey = key;
	std::vector<int> missingNumbers;
	int random;

	missingNumbers = getMissingNumbers(key);

	srand((unsigned int)time(NULL));

	for (size_t i = 0; i < filledKey.size(); i++) {
		if (filledKey[i] != -1)
			continue;

		random = rand() % missingNumbers.size();
		filledKey[i] = missingNumbers[random];

		missingNumbers.erase(missingNumbers.begin() + random);
	}

	return filledKey;
}

void writeTextToFile(const std::string & text, const std::string & filename)
{
	std::ofstream file(filename, std::ios::binary);
	file.write(text.c_str(), text.size());
	file.close();

	std::cout << "[ SUCCESS ] The encrypted text was written to " << filename << std::endl;
}

void bruteForceKeyPart(const std::string & cipherText, const std::string & openedTextPart, std::vector<int> & key, const std::string & path)
{
	std::vector<int> filledKey;
	std::string answer, decryptedText;

	for (int i = 0; i < 10; i++) {

		// try to get key that will encpypt 1/3 part of cipher correctly
		while (true) {
			filledKey = getFilledRandomKey(key);
			decryptedText = decryptText(cipherText, filledKey);

			if (openedTextPart == decryptedText.substr(0, openedTextPart.size()))
				break;
		}

		std::cout << std::endl;
		std::cout << "\tIteration       : " << i << std::endl;
		std::cout << "\tPossible key    : " << showKey(filledKey) << std::endl;
		std::cout << "\tDecipher (part) : " << decryptedText.substr(0, 40) << std::endl;

		if (i < 9) {
			std::cout << "\tDo you want to continue ? (Y/N) ";
			std::cin >> answer;

			if (answer != "y" && answer != "Y")
				break;
		}
	}

	std::cout << std::endl;
	writeTextToFile(decryptedText, path);
}

std::vector<double> calculateMatchIndexes(size_t keyLength, const std::string & cipherText, std::map <char, double> & freqAlphabet)
{
	std::vector<double> matchIndexes;
	std::string substr;
	double matchIndex;

	for (size_t i = 0; i < keyLength; i++) {

		// build string which contains elements encrypted by the same key
		for (size_t j = i; j < cipherText.size(); j += keyLength) {
			substr += cipherText[j];
		}

		// compute match index for substring
		matchIndex = 0;
		for (auto elem : freqAlphabet) {
			int count = std::count(substr.begin(), substr.end(), elem.first);
			matchIndex += count * (count - 1);
		}
		matchIndex /= (substr.size() * (substr.size() - 1));

		matchIndexes.push_back(matchIndex);
		substr.clear();
	}

	return matchIndexes;
}

double getMaxValue(std::map<int, double> & values)
{
	double maxElem = 0.0;

	for (auto elem : values) {
		if (elem.second > maxElem)
			maxElem = elem.second;
	}

	return maxElem;
}

size_t computeKeyLength(const std::string & cipherText, std::map <char, double> & freqAlphabet)
{
	std::map<int, double> averageValues;
	std::vector<double> matchIndexes;
	double matchIndexAverage;
	size_t keyLength;
	const size_t MAX_KEY_LENGTH = 100; // should be cipherText.size() / 2, but it is too long

	// for different key (substrings) lengths find match indexes
	for (keyLength = 2; keyLength < MAX_KEY_LENGTH; keyLength++) {

		matchIndexes = calculateMatchIndexes(keyLength, cipherText, freqAlphabet);
		matchIndexAverage = 0;

		for (auto elem : matchIndexes)
			matchIndexAverage += elem;

		matchIndexAverage /= matchIndexes.size();

		//std::cout << " | keyLength : " << keyLength << " | matchIndexAverage : " << matchIndexAverage << "\t|" << std::endl;

		averageValues[keyLength] = matchIndexAverage;
	}

	// search average value close to the england value
	matchIndexAverage = 0;
	for (auto elem : averageValues) {
		if (pow(elem.second - SPECIAL_VALUE, 2) < pow(matchIndexAverage - SPECIAL_VALUE, 2)) {
			matchIndexAverage = elem.second;
			keyLength = elem.first;
		}
	}

	/*
	// search average value close to the england value
	double maxAverageElem = getMaxValue(averageValues);
	for (auto elem : averageValues) {
		if (fabs(elem.second - maxAverageElem) < 0.005) {
			keyLength = elem.first;
			break;
		}
	}
	*/

	return keyLength;
}

void analyzeStringFrequencies(
	const std::string & str, 
	const std::map <char, double> & originalFreqAlphabet, 
	std::map<char, double> & stringFreqs
)
{
	int count;

	for (auto elem : originalFreqAlphabet) {
		count = std::count(str.begin(), str.end(), elem.first);
		stringFreqs[elem.first] = (double)count / str.size();
	}
}

int findKeyOffset(std::map <char, double> & originFreqAlphabet, std::map <char, double> & cipherColumnFreqAlphabet)
{
	int offset;
	int alphabetSize = originFreqAlphabet.size();
	std::map<int, double> sumOfDifferences;
	std::string alphabet;
	double sumOfDifference;
	double originFreq, cipherFreq;
	
	for (auto elem : originFreqAlphabet)
		alphabet += elem.first;

	// search difference between frequencies for different offsets
	for (offset = 0; offset < alphabetSize; offset++) {
		sumOfDifference = 0;
		for (int j = 0; j < alphabetSize; j++) {
			originFreq = originFreqAlphabet[alphabet[(j + offset) % alphabetSize]];
			cipherFreq = cipherColumnFreqAlphabet[alphabet[j]];
			sumOfDifference += abs(originFreq - cipherFreq);
		}
		sumOfDifferences[offset] = sumOfDifference;
	}

	// search min sum of differences
	offset = 0;
	for (auto elem : sumOfDifferences) {
		if (elem.second < sumOfDifferences[offset])
			offset = elem.first;
	}

	return (alphabetSize - offset);
}

int computeKeyElement(int position, int keyLength, const std::string & cipherText, std::map <char, double> & freqAlphabet)
{
	std::string columnString;
	std::map<char, double> columnStringFreqs;

	// build string with characters which have the same key
	for (size_t i = position; i < cipherText.size(); i += keyLength)
		columnString += cipherText[i];

	// get column string frequencies
	analyzeStringFrequencies(columnString, freqAlphabet, columnStringFreqs);

	return findKeyOffset(freqAlphabet, columnStringFreqs);
}

int firstFriedmanTest(const std::string & cipherText, std::map <char, double> & freqAlphabet, std::vector <int> & key)
{
	int keyLength = computeKeyLength(cipherText, freqAlphabet);

	std::cout << "[ SUCCESS ] The length of the key for Vigenere ciphertext found (" << keyLength << ")" << std::endl;

	return keyLength;
}

double calculateMutualMatchIndex(const std::string & firstString, const std::string & secondString, const std::string & alphabet)
{
	int letterCount[2];
	double mutualMatchIndex = 0;

	for (size_t i = 0; i < alphabet.size(); i++) {
		letterCount[0] = std::count(firstString.begin(), firstString.end(), alphabet[i]);
		letterCount[1] = std::count(secondString.begin(), secondString.end(), alphabet[i]);
		mutualMatchIndex += letterCount[0] * letterCount[1];
	}
	mutualMatchIndex /= (firstString.size() * secondString.size());

	return mutualMatchIndex;
}

std::map<int, double> getMutualIndexesForAllOffsets(const std::string & defaultColumn, const std::string & cipherColumn, const std::string & alphabet)
{
	std::map<int, double> mutualMatchIndexes;
	std::string offsetCipherColumn;

	// for each key offset compute mutual match index
	for (size_t offset = 0; offset < alphabet.size(); offset++) {

		for (size_t i = 0; i < cipherColumn.size(); i++) {
			int j = alphabet.find(cipherColumn[i]);
			offsetCipherColumn += alphabet[(j + offset) % alphabet.size()];
		}

		// compute mutual match index for two strings
		mutualMatchIndexes[offset] = calculateMutualMatchIndex(defaultColumn, offsetCipherColumn, alphabet);

		offsetCipherColumn.clear();
	}

	return mutualMatchIndexes;
}

int secondFriedmanTest(const std::string & cipherText, std::map <char, double> & freqAlphabet, std::vector <int> & key, size_t keyLength)
{
	std::map<int, double> mutualMatchIndexes;
	std::string alphabet;
	std::string cipherColumn, defaultColumn;
	int offset = 0;

	for (auto elem : freqAlphabet)
		alphabet += elem.first;

	// build default column which will use for computing mutual match index
	for (size_t i = 0; i < cipherText.size(); i += keyLength)
		defaultColumn += cipherText[i];

	for (size_t columnIndex = 1; columnIndex < keyLength; columnIndex++) {
		cipherColumn.clear();

		// build cipher text column (those symbols that were encrypted by the same key)
		for (size_t i = columnIndex; i < cipherText.size(); i += keyLength)
			cipherColumn += cipherText[i];

		// getting map of mutual match indexes for different offsets
		mutualMatchIndexes = getMutualIndexesForAllOffsets(defaultColumn, cipherColumn, alphabet);

		// search value close to the special value
		double mutualMatchIndex = 0;
		for (auto elem : mutualMatchIndexes) {
			if (pow(elem.second - SPECIAL_VALUE, 2) < pow(mutualMatchIndex - SPECIAL_VALUE, 2)) {
				mutualMatchIndex = elem.second;
				offset = elem.first;
			}
		}

		key[columnIndex] = (key[0] - offset + alphabet.size()) % alphabet.size();
	}

	return 0;
}

std::string decryptVigenerCipher(std::string & cipherText, std::vector<int> & key, std::map<char, double> & freqAlphabet)
{
	std::string alphabet;
	std::string decryptedString;
	size_t keyLength = key.size();
	int alphabetIndex;

	for (auto elem : freqAlphabet)
		alphabet.push_back(elem.first);

	for (size_t i = 0; i < cipherText.size(); i++) {
		alphabetIndex = alphabet.find(cipherText[i]);
		alphabetIndex += alphabet.size() - key[i % keyLength];
		while (alphabetIndex < 0)
			alphabetIndex += alphabet.size();

		decryptedString += alphabet[alphabetIndex % alphabet.size()];
	}

	return decryptedString;
}