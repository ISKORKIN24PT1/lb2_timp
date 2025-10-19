#pragma once
#include <vector>
#include <string>
#include <map>
#include <locale>
#include <stdexcept>

class cipher_error : public std::invalid_argument {
public:
    explicit cipher_error(const std::string& what_arg) : std::invalid_argument(what_arg) {}
    explicit cipher_error(const char* what_arg) : std::invalid_argument(what_arg) {}
};

class modTableCipher {
private:
    int key;

    std::wstring encryptImpl(const std::wstring& open_text);
    std::wstring decryptImpl(const std::wstring& cipher_text);
    static std::wstring prepareText(const std::wstring& text);
    static wchar_t toUpper(wchar_t c);
    int getValidKey(const int k);
    std::wstring getValidOpenText(const std::wstring& s);
    std::wstring getValidCipherText(const std::wstring& s);
    
public:
    modTableCipher() = delete;
    modTableCipher(int skey);
    std::wstring encrypt(const std::wstring& open_text);
    std::wstring decrypt(const std::wstring& cipher_text);
};
