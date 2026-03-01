// Класс шифра Виженера для русского языка
export class VigenereCipher {
    constructor() {
        // Русский алфавит (33 буквы)
        this.alphabet = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ';
        this.alphabetSize = this.alphabet.length;
    }

    // Очистка текста (только русские буквы)
    cleanText(text) {
        if (!text) return '';
        text = text.toUpperCase();
        let result = '';
        for (let char of text) {
            if (this.alphabet.includes(char)) {
                result += char;
            }
        }
        return result;
    }

    // Подготовка ключа (повторяем до длины текста)
    prepareKey(text, key) {
        key = this.cleanText(key);
        if (key.length === 0) return '';
        
        let preparedKey = '';
        let keyIndex = 0;
        
        for (let i = 0; i < text.length; i++) {
            preparedKey += key[keyIndex % key.length];
            keyIndex++;
        }
        
        return preparedKey;
    }

    // Шифрование (прямой ключ: C = (P + K) mod N)
    encrypt(plaintext, key) {
        plaintext = this.cleanText(plaintext);
        key = this.cleanText(key);
        
        if (plaintext.length === 0) return '';
        if (key.length === 0) return plaintext;

        const preparedKey = this.prepareKey(plaintext, key);
        let ciphertext = '';

        for (let i = 0; i < plaintext.length; i++) {
            const plainIndex = this.alphabet.indexOf(plaintext[i]);
            const keyIndex = this.alphabet.indexOf(preparedKey[i]);
            // Прямой ключ: складываем индексы
            const encryptedIndex = (plainIndex + keyIndex) % this.alphabetSize;
            ciphertext += this.alphabet[encryptedIndex];
        }

        return ciphertext;
    }

    // Дешифрование (обратный ключ: P = (C - K + N) mod N)
    decrypt(ciphertext, key) {
        ciphertext = this.cleanText(ciphertext);
        key = this.cleanText(key);
        
        if (ciphertext.length === 0) return '';
        if (key.length === 0) return ciphertext;

        const preparedKey = this.prepareKey(ciphertext, key);
        let plaintext = '';

        for (let i = 0; i < ciphertext.length; i++) {
            const cipherIndex = this.alphabet.indexOf(ciphertext[i]);
            const keyIndex = this.alphabet.indexOf(preparedKey[i]);
            // Вычитаем ключ для дешифрования
            const decryptedIndex = (cipherIndex - keyIndex + this.alphabetSize) % this.alphabetSize;
            plaintext += this.alphabet[decryptedIndex];
        }

        return plaintext;
    }

    // Проверка, содержит ли текст русские буквы
    containsRussian(text) {
        const russianRegex = /[А-Яа-яЁё]/;
        return russianRegex.test(text);
    }
}