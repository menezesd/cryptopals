#include <unordered_map>
#include <string>
#include <cmath>
#include <algorithm>
#include <vector>
#include <iostream>
#include <fstream>
using namespace std;

double score_decrypted_bytes(const string& b) {
    double score = 0;
    for (auto c : b) {
      score += (c == ' ') || ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z');
    }
    return score;
}

string decrypt_single_byte_xor_with_key(const string& b, char key_byte) {
    string key(b.size(), key_byte);
    string result;
    transform(b.begin(), b.end(), key.begin(), back_inserter(result), bit_xor<>{});
    return result;
}

vector<tuple<string, char, double>> decrypt_single_byte_xor(const string& b, int num_candidates = 1) {
    unordered_map<char, double> key_scores;
    for (int key_byte = 0; key_byte < 256; ++key_byte) {
        auto decrpytion = decrypt_single_byte_xor_with_key(b, static_cast<char>(key_byte));
        key_scores[static_cast<char>(key_byte)] = score_decrypted_bytes(decrpytion);
    }
    vector<tuple<char, double>> result(key_scores.begin(), key_scores.end());
    sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return get<1>(a) > get<1>(b); });
    result.resize(num_candidates);
    vector<tuple<string, char, double>> decrypted_candidates;
    for (const auto& [key_byte, score] : result) {
        decrypted_candidates.emplace_back(decrypt_single_byte_xor_with_key(b, key_byte), key_byte, score);
    }
    return decrypted_candidates;
}





string decode_hex(const std::string& hex_string) {
  string bytes;
  for (std::size_t i = 0; i < hex_string.size(); i += 2) {
    unsigned char byte = std::stoi(hex_string.substr(i, 2), nullptr, 16);
    bytes.push_back(byte);
  }
  return bytes;
}

int main ()
{
  ifstream f("4.txt");
  string s;
  while (!f.eof()) {
    getline(f, s);
    string b = decode_hex(s);
    auto [str, c, score] = decrypt_single_byte_xor(b, 1)[0];
    if (score < str.size() * 0.88) continue;
    cout << "Ciphertext: " << s << endl;
    cout << str << endl;
  }
}
