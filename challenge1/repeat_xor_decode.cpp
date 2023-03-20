#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <iterator>
#include <climits>
using namespace std;

vector<uint8_t> bxor(const vector<uint8_t> &a, const vector<uint8_t> &b)
{
	// bitwise XOR of byte vectors
	vector<uint8_t> result;
	transform(a.begin(), a.end(), b.begin(), back_inserter(result),
		  [](uint8_t x, uint8_t y) { return x ^ y; });
	return result;
}

int hamming_distance(const vector<uint8_t> &a, const vector<uint8_t> &b)
{
	// returns the Hamming distance of two byte vectors
	vector<uint8_t> xored = bxor(a, b);
	return accumulate(xored.begin(), xored.end(), 0,
			  [](int acc, uint8_t byte) {
				  return acc + __builtin_popcount(byte);
			  });
}

struct candidate {
	vector<uint8_t> message;
	int nb_letters;
	uint8_t key;
};

candidate attack_single_byte_xor(const vector<uint8_t> &ciphertext)
{
	// a variable to keep track of the best candidate so far
	candidate best;
	best.nb_letters = 0;
	for (int i = 0; i < 256; i++) {
		// converting the key from a number to a byte
		vector<uint8_t> keystream(ciphertext.size(), i);
		vector<uint8_t> candidate_message = bxor(ciphertext, keystream);

		int nb_letters =
			count_if(candidate_message.begin(),
				 candidate_message.end(), [](uint8_t byte) {
					 return (byte >= 'a' && byte <= 'z') ||
						(byte >= 'A' && byte <= 'Z') ||
						(byte == ' ');
				 });
		// if the obtained message has more letters than any other candidate before
		if (best.message.empty() || nb_letters > best.nb_letters) {
			// store the current key and message as our best candidate so far
			best = { candidate_message, nb_letters,
				 static_cast<uint8_t>(i) };
		}
	}

	return best;
}

double score_vigenere_key_size(int k, const vector<uint8_t> &ciphertext)
{
	int num_measurements = ciphertext.size() / k - 1;
	double score = 0;
	for (int i = 0; i < num_measurements; i++) {
		score += hamming_distance(
			vector<uint8_t>(ciphertext.begin() + i * k,
					ciphertext.begin() + i * k + k),
			vector<uint8_t>(ciphertext.begin() + i * k + k,
					ciphertext.begin() + i * k + 2 * k));
	}
	score /= k;
	score /= num_measurements;
	return score;
}

int find_vigenere_key_length(const vector<uint8_t> &ciphertext,
			     int min_length = 2, int max_length = 30)
{
	auto key = [&ciphertext](int k) {
		return score_vigenere_key_size(k, ciphertext);
	};
	int len = 2, bscore = INT_MAX;
	for (int i = min_length; i <= max_length; i++) {
		int cur = key(i);
		if (cur < bscore) {
			bscore = cur;
			len = i;
		}
	}
	return len;
}

struct attack_result {
	string message;
	string key;
};

// Function to attack repeating-key XOR encryption using Vigenere cipher
attack_result attack_repeating_key_xor(const vector<uint8_t> &ciphertext)
{
	int keysize = find_vigenere_key_length(ciphertext);
	string key = "";
	vector<vector<uint8_t> > message_parts;
	for (int i = 0; i < keysize; i++) {
		vector<uint8_t> part;
		for (int j = i; j < ciphertext.size(); j += keysize) {
			part.push_back(ciphertext[j]);
		}
		auto result = attack_single_byte_xor(part);
		key += result.key;
		message_parts.push_back(result.message);
	}

	string message = string(ciphertext.size(), ' ');
	for (int i = 0; i < keysize; i++) {
		const auto &part = message_parts[i];
		for (int j = 0; j < part.size(); j++) {
			message[j * keysize + i] = part[j];
		}
	}
	return attack_result{ message, key };
}

int main()
{
	// open the file:
	std::streampos fileSize;
	std::ifstream file("6.bin", std::ios::binary);

	// get its size:
	file.seekg(0, std::ios::end);
	fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	// read the data:
	std::vector<uint8_t> fileData(fileSize);
	file.read((char *)&fileData[0], fileSize);
	auto res = attack_repeating_key_xor(fileData);

	cout << res.message << "\n";
	cout << res.key << "\n";
}
