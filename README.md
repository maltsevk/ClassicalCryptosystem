# ClassicalCryptosystem
It's a classical cryptosystem that uses vertical permutation and Vigenere cipher.

Vertical permutation. The size of the table is determined based on the size of the alphabet, i.e. is the divisor of the number of characters in opened text (the divisor must be greater than 2). If the number is simple, you need to add another one or two characters to the opened text. The key is generated by the program automatically and displayed on the screen (console).

Encryptor input:
* binary file with an opened text to be encrypted.
Encryptor output:
* file with an opened text alphabet and frequencies of characters;
* binary file with an text encrypted by vertical permutation;
* binary file with an text encrypted by Vigenere cipher.
