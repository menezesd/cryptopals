#include <iostream>
#include <vector>
#include <cassert>
#include <string>

std::vector<unsigned char> decode_hex(const std::string &hex_string)
{
	std::vector<unsigned char> bytes;
	for (std::size_t i = 0; i < hex_string.size(); i += 2) {
		unsigned char byte =
			std::stoi(hex_string.substr(i, 2), nullptr, 16);
		bytes.push_back(byte);
	}
	return bytes;
}

std::vector<unsigned char> xor_buf(const std::string &b1, const std::string &b2)
{
	std::vector<unsigned char> result(b1.size());
	for (std::size_t i = 0; i < b1.size(); i++) {
		result[i] = b1[i] ^ b2[i % b2.size()];
	}
	return result;
}

int main()
{
	std::string hex_result =
		"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
		"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

	std::string b1 =
		"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	std::string b2 = "ICE";
	std::vector<unsigned char> result = decode_hex(hex_result);

	std::vector<unsigned char> xored = xor_buf(b1, b2);
	if (xored == result) {
		std::cout << "XOR result is correct!" << std::endl;
	} else {
		std::cout << "XOR result is incorrect!" << std::endl;
	}
	return 0;
}
