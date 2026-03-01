// Класс для шифра Плейфера с 4 матрицами (английский язык)
export class PlayfairCipher {
    constructor() {
        // Английский алфавит без J (I и J вместе)
        this.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
    }

    // Подготовка текста для английского языка
    prepareText(text) {
        return text
            .toUpperCase()
            .replace(/\s+/g, '')
            .replace(/[^A-Z]/g, '')  // Только английские буквы
            .replace(/J/g, 'I');      // Заменяем J на I
    }

    // Создание матрицы 5x5 из ключа
    createMatrix(key) {
        // Очищаем ключ
        key = this.prepareText(key);
        
        // Создаем массив из алфавита
        let alfaArray = this.alphabet.split('');
        let form = '';
        
        // Удаляем дубликаты из ключа
        let keyArray = key.split('');
        for (let i = 0; i < keyArray.length; i++) {
            for (let j = i + 1; j < keyArray.length; j++) {
                if (keyArray[i] == keyArray[j]) {
                    keyArray.splice(j, 1);
                    j--;
                }
            }
        }

        // Удаляем символы ключа из алфавита
        for (let i = 0; i < keyArray.length; i++) {
            for (let j = 0; j < alfaArray.length; j++) {
                if (keyArray[i] == alfaArray[j]) {
                    alfaArray.splice(j, 1);
                    j--;
                }
            }
        }

        // Формируем строку для матрицы: ключ + оставшийся алфавит
        let alfa = alfaArray.join('');
        key = keyArray.join('');
        form = key + alfa;

        // Создаем матрицу 5x5
        let formArray = form.split('');
        let matrix = new Array(5);
        for (let i = 0; i < 5; i++) {
            matrix[i] = new Array(5);
        }

        let count = 0;
        for (let i = 0; i < 5; i++) {
            for (let j = 0; j < 5; j++) {
                if (formArray[count] == 'I') {
                    matrix[i][j] = 'I/J';
                } else {
                    matrix[i][j] = formArray[count];
                }
                count++;
            }
        }

        return matrix;
    }

    // Создание биграмм из текста
createBigrams(text) {
    // Очищаем текст
    text = this.prepareText(text);
    let arrayT = text.split('');
    let result = [];
    
    // Проходим по всем символам
    for (let i = 0; i < arrayT.length; i++) {
        result.push(arrayT[i]);
        
        // Если текущий символ - X и следующий тоже X
        if (arrayT[i] == 'X' && i + 1 < arrayT.length && arrayT[i + 1] == 'X') {
            result.push('Z'); // Вставляем Z между X
        }
        
        // Если два одинаковых символа и они не X
        if (i + 1 < arrayT.length && arrayT[i] == arrayT[i + 1] && arrayT[i] != 'X') {
            result.push('X'); // Вставляем X между одинаковыми буквами
        }
    }
    
    // Если нечетное количество символов, добавляем X в конец
    if (result.length % 2 == 1) {
        result.push('X');
    }

    // Создаем пары
    let pairs = [];
    for (let i = 0; i < result.length; i += 2) {
        let pair = result[i] + result[i + 1];
        pairs.push(pair);   
    }

    return pairs;
}

// Очистка результата от служебных символов
cleanResult(text) {if (!text) return '';
if (!text) return '';

    // Шаг 1: убираем Z между X
    let s = text;
    let prev;
    do {
        prev = s;
        let temp = '';
        let i = 0;
        while (i < s.length) {
            if (i + 2 < s.length && s[i] === 'X' && s[i+1] === 'Z' && s[i+2] === 'X') {
                temp += 'XX';
                i += 3;
            } else {
                temp += s[i];
                i++;
            }
        }
        s = temp;
    } while (s !== prev);

    // Шаг 2: убираем последний X если заканчивается на XX
    if (s.length >= 2 && s.endsWith('XX')) {
        s = s.slice(0, -1);
    }

    // Шаг 3: убираем одиночный X между одинаковыми буквами
    let result = '';
    let i = 0;
    while (i < s.length) {
        if (i + 2 < s.length &&
            s[i + 1] === 'X' &&
            s[i] === s[i + 2] &&
            s[i] !== 'X') {

            result += s[i];
            i += 2;
        } else {
            result += s[i];
            i++;
        }
        if (result.endsWith('X') && (i == s.length)) {
        result = result.slice(0, -1);
    }
    }

   

    return result;
}

    // Поиск координат символа в матрице
    findCoordinates(char, matrix) {
        // Обработка I/J
        let searchChar = char;
        if (char === 'I' || char === 'J') {
            searchChar = 'I/J';
        }

        for (let row = 0; row < 5; row++) {
            for (let col = 0; col < 5; col++) {
                if (matrix[row][col] === searchChar || 
                    (searchChar === 'I/J' && (matrix[row][col] === 'I' || matrix[row][col] === 'I/J'))) {
                    return { row, col };
                }
            }
        }
        return null;
    }

    // Шифрование с 4 матрицами
    encrypt(plaintext, key1, key2, key3, key4) {
        // Создаем матрицы
        const M1 = this.createMatrix(key1);
        const M2 = this.createMatrix(key2);
        const M3 = this.createMatrix(key3);
        const M4 = this.createMatrix(key4);

        // Создаем биграммы
        const bigrams = this.createBigrams(plaintext);
        let ciphertext = '';

        // Для каждой биграммы
        for (const pair of bigrams) {
            // Находим координаты первого символа в M2
            const coord1 = this.findCoordinates(pair[0], M2);
            // Находим координаты второго символа в M4
            const coord2 = this.findCoordinates(pair[1], M4);

            if (coord1 && coord2) {
                // Берем символы из M1 и M3 по тем же координатам
                let char1 = M1[coord1.row][coord1.col];
                let char2 = M3[coord2.row][coord2.col];
                
                // Заменяем I/J на I для выходного текста
                ciphertext += char1 === 'I/J' ? 'I' : char1;
                ciphertext += char2 === 'I/J' ? 'I' : char2;
            }
        }

        return ciphertext;
    }

    // Дешифрование с 4 матрицами
    decrypt(ciphertext, key1, key2, key3, key4) {
        // Создаем матрицы
        const M1 = this.createMatrix(key1);
        const M2 = this.createMatrix(key2);
        const M3 = this.createMatrix(key3);
        const M4 = this.createMatrix(key4);

        // Создаем биграммы
        const bigrams = this.createBigrams(ciphertext);
        let plaintext = '';

        // Для каждой биграммы
        for (const pair of bigrams) {
            // Находим координаты первого символа в M1
            const coord1 = this.findCoordinates(pair[0], M1);
            // Находим координаты второго символа в M3
            const coord2 = this.findCoordinates(pair[1], M3);

            if (coord1 && coord2) {
                // Берем символы из M2 и M4 по тем же координатам
                let char1 = M2[coord1.row][coord1.col];
                let char2 = M4[coord2.row][coord2.col];
                
                // Заменяем I/J на I для выходного текста
                plaintext += char1 === 'I/J' ? 'I' : char1;
                plaintext += char2 === 'I/J' ? 'I' : char2;
            }
        }

        // Очищаем результат от служебных символов
        return this.cleanResult(plaintext);
    }

    // Получить все матрицы для визуализации
    getMatrices(key1, key2, key3, key4) {
        return {
            M1: this.createMatrix(key1),
            M2: this.createMatrix(key2),
            M3: this.createMatrix(key3),
            M4: this.createMatrix(key4)
        };
    }

    // Визуализация матрицы в HTML
    renderMatrix(matrix, elementId, keyValue = '') {
        const container = document.getElementById(elementId);
        if (!container) return;
        
        container.innerHTML = '';
        
        for (let i = 0; i < 5; i++) {
            for (let j = 0; j < 5; j++) {
                const cell = document.createElement('div');
                cell.className = 'matrix-cell';
                cell.textContent = matrix[i][j];
                container.appendChild(cell);
            }
        }

        // Обновляем отображение ключа
        const keyElement = document.getElementById('matrixKey' + elementId.slice(-1));
        if (keyElement && keyValue) {
            keyElement.textContent = `(ключ: ${keyValue})`;
        }
    }

    // Проверка, содержит ли текст английские буквы
    containsEnglish(text) {
        const englishRegex = /[A-Za-z]/;
        return englishRegex.test(text);
    }
    
    // Тестовый метод для проверки работы
    test() {
        console.log('=== Тестирование Playfair Cipher ===');
        
        const testCases = [
            {
                name: 'Обычный текст',
                text: 'HELLO',
                key1: 'CRYPTO',
                key2: 'GRAPHY',
                key3: 'SECURE',
                key4: 'MESSAGE'
            },
            {
                name: 'Текст с последовательностью X',
                text: 'HELXLOXXXWORLD',
                key1: 'CRYPTO',
                key2: 'GRAPHY',
                key3: 'SECURE',
                key4: 'MESSAGE'
            },
            {
                name: 'Текст с дубликатами',
                text: 'AABBCC',
                key1: 'CRYPTO',
                key2: 'GRAPHY',
                key3: 'SECURE',
                key4: 'MESSAGE'
            }
        ];
        
        for (const test of testCases) {
            console.log(`\nТест: ${test.name}`);
            console.log(`Исходный текст: ${test.text}`);
            
            const encrypted = this.encrypt(test.text, test.key1, test.key2, test.key3, test.key4);
            console.log(`Зашифровано: ${encrypted}`);
            
            const decrypted = this.decrypt(encrypted, test.key1, test.key2, test.key3, test.key4);
            console.log(`Расшифровано: ${decrypted}`);
            
            console.log(`Результат: ${test.text === decrypted ? '✓ УСПЕХ' : '✗ ОШИБКА'}`);
        }
    }
}   