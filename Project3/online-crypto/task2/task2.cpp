#include <iostream>
#include <string>
#include <stdio.h>
using namespace std;

string enum_key(string current) {
    /*Return the next key based on the current key as hex string.

     TODO: Implement the required functions.
     */
	return "Your should implement this function! We are going to test it!";
}

int main(int argc, char* argv[]) {
	string mode = argv[1];
	if (mode == "enum_key") {
		printf("%s", enum_key(argv[2]).c_str());
	} else if (mode == "crack") {
		// TODO: Add your own code and do whatever you do.
	} else {
		printf("Wrong mode!");
	}
	return 0;
}
