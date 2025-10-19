#include "modTableCipher.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cwctype>

modTableCipher::modTableCipher(int skey) : key(getValidKey(skey)) {}

int modTableCipher::getValidKey(const int k) {
    if (k == 0) {
        throw cipher_error("Invalid key: cannot be zero");
    }
    if (k < 0) {
        throw cipher_error("Invalid key: cannot be negative");
    }
    if (k > 100) {
        throw cipher_error("Invalid key: too large");
    }
    return k;
}

wchar_t modTableCipher::toUpper(wchar_t c) {
    if (c >= L'а' && c <= L'я') {
        return L'А' + (c - L'а');
    }
    if (c == L'ё') {
        return L'Ё';
    }
    return std::towupper(c);
}

std::wstring modTableCipher::getValidOpenText(const std::wstring& s) {
    std::wstring prepared = prepareText(s);
    if (prepared.empty()) {
        throw cipher_error("Empty text: no valid Russian letters");
    }
    return prepared;
}

std::wstring modTableCipher::getValidCipherText(const std::wstring& s) {
    if (s.empty()) {
        throw cipher_error("Empty cipher text");
    }
    for (wchar_t c : s) {
        if (!((c >= L'А' && c <= L'Я') || c == L'Ё' || c == L'X')) {
            throw cipher_error("Invalid cipher text: must contain only Russian uppercase letters or X");
        }
    }
    return s;
}

std::wstring modTableCipher::prepareText(const std::wstring& text) {
    std::wstring result;
    for (wchar_t c : text) {
        wchar_t upperC = toUpper(c);
        if ((upperC >= L'А' && upperC <= L'Я') || upperC == L'Ё') {
            result += upperC;
        }
    }
    return result;
}

std::wstring modTableCipher::encryptImpl(const std::wstring& open_text) {
    std::wstring prepared_text = open_text;
    int len = prepared_text.length();
    
    int rows = (len + key - 1) / key;
    int total_cells = rows * key;
    int pad_chars = total_cells - len;
    
    std::wstring text_with_pad = prepared_text;
    for (int i = 0; i < pad_chars; i++) {
        text_with_pad += L'X';
    }
    
    std::vector<std::vector<wchar_t>> table(rows, std::vector<wchar_t>(key));
    
    int index = 0;
    for (int row = 0; row < rows; row++) {
        for (int col = 0; col < key; col++) {
            table[row][col] = text_with_pad[index++];
        }
    }

    std::wstring result;
    for (int col = key - 1; col >= 0; col--) {
        for (int row = 0; row < rows; row++) {
            result += table[row][col];
        }
    }

    return result;
}

std::wstring modTableCipher::decryptImpl(const std::wstring& cipher_text) {
    std::wstring text_to_process = cipher_text;
    int len = text_to_process.length();
    
    int rows = len / key; 
    
    std::vector<std::vector<wchar_t>> table(rows, std::vector<wchar_t>(key));

    int index = 0;
    for (int col = key - 1; col >= 0; col--) {
        for (int row = 0; row < rows; row++) {
            table[row][col] = text_to_process[index++];
        }
    }

    std::wstring result_with_pad;
    for (int row = 0; row < rows; row++) {
        for (int col = 0; col < key; col++) {
            result_with_pad += table[row][col];
        }
    }

    std::wstring result;
    for (wchar_t c : result_with_pad) {
        if (c != L'X') {
            result += c;
        }
    }

    return result;
}

std::wstring modTableCipher::encrypt(const std::wstring& open_text) {
    return encryptImpl(getValidOpenText(open_text));
}

std::wstring modTableCipher::decrypt(const std::wstring& cipher_text) {
    return decryptImpl(getValidCipherText(cipher_text));
}
