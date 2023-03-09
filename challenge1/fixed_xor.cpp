#include <iostream>
#include <vector>
#include <cassert>

std::vector<unsigned char> decode_hex(const std::string& hex_string) {
    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < hex_string.size(); i += 2) {
        unsigned char byte = std::stoi(hex_string.substr(i, 2), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<unsigned char> xor_buf(const std::vector<unsigned char>& b1, const std::vector<unsigned char>& b2) {
    assert(b1.size() == b2.size());
    std::vector<unsigned char> result(b1.size());
    for (std::size_t i = 0; i < b1.size(); i++) {
        result[i] = b1[i] ^ b2[i];
    }
    return result;
}

int main() {
    std::string hex_str1 = "1c0111001f010100061a024b53535009181c";
    std::string hex_str2 = "686974207468652062756c6c277320657965";
    std::string hex_result = "746865206b696420646f6e277420706c6179";

    std::vector<unsigned char> b1 = decode_hex(hex_str1);
    std::vector<unsigned char> b2 = decode_hex(hex_str2);
    std::vector<unsigned char> result = decode_hex(hex_result);

    std::vector<unsigned char> xored = xor_buf(b1, b2);
    if (xored == result) {
        std::cout << "XOR result is correct!" << std::endl;
    } else {
        std::cout << "XOR result is incorrect!" << std::endl;
    }
    return 0;
}
