#include <iostream>
#include <locale>
#include "modTableCipher.h"

using namespace std;

void test(const wstring& text, int key) {
    try {
        modTableCipher cipher(key);
        wstring encrypted = cipher.encrypt(text);
        wstring decrypted = cipher.decrypt(encrypted);
        
        wcout << L"Key: " << key << L" | Text: '" << text << L"'" << endl;
        wcout << L"Encrypted: '" << encrypted << L"'" << endl;
        wcout << L"Decrypted: '" << decrypted << L"'" << endl;
        wcout << endl;
    } catch (const cipher_error& e) {
        wcout << L"Error with key " << key << L" and text '" << text << L"': " << e.what() << endl << endl;
    }
}

int main() {
    setlocale(LC_ALL, "");
    
    wcout << L"=== ТЕСТИРОВАНИЕ ТАБЛИЧНОЙ МАРШРУТНОЙ ПЕРЕСТАНОВКИ ===" << endl << endl;
    
    wcout << L"1. КОРРЕКТНЫЕ ДАННЫЕ:" << endl;
    test(L"Добрый вечер", 4);
    test(L"СЁМГА", 2);
    test(L"ПРИВЕТ мир", 3);
    test(L"АБВГД", 2);
    
    wcout << L"2. ТЕСТЫ С ОШИБКАМИ:" << endl;
    test(L"Добрый вечер", 0);   // Неверный ключ
    test(L"Добрый вечер", -5);  // Отрицательный ключ
    test(L"Добрый вечер", 150); // Слишком большой ключ
    test(L"123!@#", 3);         // Текст без русских букв
    test(L"", 3);               // Пустой текст
    
    return 0;
}
