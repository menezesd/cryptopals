#include <iostream>
#include <string>

using namespace std;

string pkcs7_pad(const string& message, int block_size) {
    // If the length of the given message is already equal to the block size, there is no need to pad
    if (message.size() == block_size) {
        return message;
    }

    // Otherwise compute the padding byte and return the padded message
    char ch = block_size - message.size() % block_size;
    string padded_message = message;
    padded_message.append(ch, ch);
    return padded_message;
}

bool is_pkcs7_padded(const string& binary_data) {
    // Take what we expect to be the padding
    int padding_len = binary_data[binary_data.size() - 1];
    string padding = binary_data.substr(binary_data.size() - padding_len);

    // Check that all the bytes in the range indicated by the padding are equal to the padding value itself
    for (int i = 0; i < padding_len; i++) {
        if (padding[i] != padding_len) {
            return false;
        }
    }
    return true;
}

string pkcs7_unpad(const string& data) {
    // Check that the input data contains at least one byte
    if (data.size() == 0) {
        throw runtime_error("The input data must contain at least one byte");
    }

    // If the data is not padded, return it as is
    if (!is_pkcs7_padded(data)) {
        return data;
    }

    // Otherwise unpad the data and return it
    int padding_len = data[data.size() - 1];
    string unpadded_data = data.substr(0, data.size() - padding_len);
    return unpadded_data;
}

int main() {
    string message = "YELLOW SUBMARINE";
    string b = pkcs7_pad(message, 20);

    // Check that the padding and unpadding methods work properly
    string unpadded_b = pkcs7_unpad(b);
    if (unpadded_b == message) {
        cout << "Padding and unpadding works properly" << endl;
    } else {
        cout << "Padding and unpadding does not work properly" << endl;
    }

    return 0;
}

