#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include "des.h"

using namespace std;


string GetHexFromBin(string sBinary) {
	string rest = "", tmp;
	for (int i = 0; i < sBinary.length(); i+=4)
	{
		tmp = sBinary.substr(i,4);
		if (!tmp.compare("0000"))
		{
			rest = rest + "0";
		}
		else if (!tmp.compare("0001"))
		{
			rest = rest + "1";
		}
		else if (!tmp.compare("0010"))
		{
			rest = rest + "2";
		}
		else if (!tmp.compare("0011"))
		{
			rest = rest + "3";
		}
		else if (!tmp.compare("0100"))
		{
			rest = rest + "4";
		}
		else if (!tmp.compare("0101"))
		{
			rest = rest + "5";
		}
		else if (!tmp.compare("0110"))
		{
			rest = rest + "6";
		}
		else if (!tmp.compare("0111"))
		{
			rest = rest + "7";
		}
		else if (!tmp.compare("1000"))
		{
			rest = rest + "8";
		}
		else if (!tmp.compare("1001"))
		{
			rest = rest + "9";
		}
		else if (!tmp.compare("1010"))
		{
			rest = rest + "A";
		}
		else if (!tmp.compare("1011"))
		{
			rest = rest + "B";
		}
		else if (!tmp.compare("1100"))
		{
			rest = rest + "C";
		}
		else if (!tmp.compare("1101"))
		{
			rest = rest + "D";
		}
		else if (!tmp.compare("1110"))
		{
			rest = rest + "E";
		}
		else if (!tmp.compare("1111"))
		{
			rest = rest + "F";
		}
		else
		{
			continue;
		}
	}
	return rest;
}

string bool_to_string(bool* array, int size=64) {
	string res;
	for (int i = 0; i < size; i++) {
		if (array[i]) {
			res += "1";
		} else {
			res += "0";
		}
	}
	return res;
}

void test_des(bool key[64], bool message[64]) {
	bool ciphertext[64] = { [0 ... 63] = false };
	EncryptDES(key, message, ciphertext);
	// suppress output
	cout << GetHexFromBin(bool_to_string(ciphertext)) << endl;
}

void test() {
	bool k[64] = { [0 ... 63] = false }, message[64] = { [0 ... 63] = false };
	test_des(k, message);
	message[63] = true;
	test_des(k, message);
	k[62] = true;
	message[63] = false;
	test_des(k, message);
	message[63] = true;
	test_des(k, message);
}

string cbc_encrypt(string message, string key, string iv) {
	// TODO: add your code here
	test();
	return "";
}

string cbc_decrypt(string message, string key, string iv) {
	// TODO: add your code here
	test();
	return "";
}

string read_from_file(string infile) {
	ifstream in(infile);
	stringstream buffer;
	buffer << in.rdbuf();
	in.close();
	return buffer.str();
}

void write_to_file(string output, string outfile) {
	ofstream out(outfile);
	out << output;
	out.close();
}

int main(int argc, char* argv[]) {
	if (argc != 6) {
		cout << "Wrong number of arguments!\n./des $MODE $INFILE $KEYFILE $IVFILE $OUTFILE\n";
		return 1;
	}
	string mode = argv[1];
	string infile = argv[2];
	string keyfile = argv[3];
	string ivfile = argv[4];
	string outfile = argv[5];
	string input = read_from_file(infile);
	string key = read_from_file(keyfile);
	string iv = read_from_file(ivfile);
	string output;
	struct timeval t_start, t_end;
	gettimeofday(&t_start, NULL);
	if (mode == "enc") {
		output = cbc_encrypt(input, key, iv);
	} else if (mode == "dec") {
		output = cbc_decrypt(input, key, iv);
	} else {
		printf("Wrong mode!");
	}
	gettimeofday(&t_end, NULL);
	printf("Consumed CPU time=%f\n", ((t_end.tv_sec * 1000000.0 + t_end.tv_usec) - (t_start.tv_sec * 1000000.0 + t_start.tv_usec)) / 1000000.0);
	write_to_file(output, outfile);
	return 0;
}
