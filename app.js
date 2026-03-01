import { VigenereCipher } from './vigenere.js';
import { PlayfairCipher } from './playfair.js';

// Главный класс приложения
class VigenereApp {
    constructor() {
        this.vigenere = new VigenereCipher();
        this.playfair = new PlayfairCipher();
        this.currentAlgorithm = 'vigenere';
        this.showVigenereTable = true; // Состояние отображения таблицы
        
        this.initializeElements();
        this.attachEvents();
        this.updateStats();
        this.updateUI();
        
        // Создаем таблицу Виженера
        this.createVigenereTable();
    }

    initializeElements() {
        // Основные элементы
        this.inputText = document.getElementById('inputText');
        this.outputText = document.getElementById('outputText');
        this.textLength = document.getElementById('textLength');
        this.keyCount = document.getElementById('keyCount');
        this.lettersOnly = document.getElementById('lettersOnly');
        this.toast = document.getElementById('toast');
        this.toastMessage = document.getElementById('toastMessage');
        this.languageIndicator = document.getElementById('currentLanguage');
        
        // Элементы для файлов
        this.fileInput = document.getElementById('fileInput');
        this.fileName = document.getElementById('fileName');
        
        // Кнопки алгоритмов
        this.btnVigenere = document.getElementById('btnVigenere');
        this.btnPlayfair = document.getElementById('btnPlayfair');
        
        // Контейнеры ключей
        this.vigenereKeys = document.getElementById('vigenereKeys');
        this.playfairKeys = document.getElementById('playfairKeys');
        
        // Поля ключей
        this.vigenereKey = document.getElementById('vigenereKey');
        this.playfairKey1 = document.getElementById('playfairKey1');
        this.playfairKey2 = document.getElementById('playfairKey2');
        this.playfairKey3 = document.getElementById('playfairKey3');
        this.playfairKey4 = document.getElementById('playfairKey4');
        
        // Визуализация
        this.matrixVisualization = document.getElementById('matrixVisualization');
        this.vigenereTableSection = document.getElementById('vigenereTableSection');
        this.vigenereTableContainer = document.getElementById('vigenereTableContainer');
        this.vigenereTableToggle = document.getElementById('vigenereTableToggle');
        this.encryptionExample = document.getElementById('encryptionExample');
        this.exampleContent = document.getElementById('exampleContent');
        
        // ИСПРАВЛЕНО: Добавляем ссылку на элемент таблицы
        this.vigenereTableElement = document.getElementById('vigenereTable');
        
        this.matrixElements = {
            M1: 'matrix1',
            M2: 'matrix2',
            M3: 'matrix3',
            M4: 'matrix4'
        };
        this.matrixKeyElements = {
            M1: 'matrixKey1',
            M2: 'matrixKey2',
            M3: 'matrixKey3',
            M4: 'matrixKey4'
        };
    }

    attachEvents() {
        // Обновление статистики при вводе
        this.inputText.addEventListener('input', () => {
            this.updateStats();
            this.updateLanguageIndicator();
        });
        
        this.vigenereKey.addEventListener('input', () => {
            this.updateStats();
        });
        
        this.playfairKey1.addEventListener('input', () => {
            this.updateStats();
            this.updateMatrixVisualization();
        });
        this.playfairKey2.addEventListener('input', () => {
            this.updateStats();
            this.updateMatrixVisualization();
        });
        this.playfairKey3.addEventListener('input', () => {
            this.updateStats();
            this.updateMatrixVisualization();
        });
        this.playfairKey4.addEventListener('input', () => {
            this.updateStats();
            this.updateMatrixVisualization();
        });
        
        // Обработка Enter
        this.vigenereKey.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.encrypt();
        });
        
        // Добавляем обработчики для всех ключей Плейфера
        [this.playfairKey1, this.playfairKey2, this.playfairKey3, this.playfairKey4].forEach(key => {
            key.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.encrypt();
            });
        });

        // Обработчик загрузки файла
        this.fileInput.addEventListener('change', (e) => this.handleFileUpload(e));
    }

    // ИСПРАВЛЕНО: Создание таблицы Виженера
    createVigenereTable() {
        if (!this.vigenereTableElement) return;
        
        const alphabet = this.vigenere.alphabet;
        const size = alphabet.length;
        
        // Очищаем таблицу
        this.vigenereTableElement.innerHTML = '';
        
        // Создаем заголовок таблицы (thead)
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        
        // Пустая ячейка в углу
        const cornerCell = document.createElement('th');
        cornerCell.textContent = 'Ключ \\ Текст';
        headerRow.appendChild(cornerCell);
        
        // Верхняя строка - символы исходного текста
        for (let i = 0; i < size; i++) {
            const th = document.createElement('th');
            th.textContent = alphabet[i];
            headerRow.appendChild(th);
        }
        thead.appendChild(headerRow);
        this.vigenereTableElement.appendChild(thead);
        
        // Создаем тело таблицы (tbody)
        const tbody = document.createElement('tbody');
        
        for (let row = 0; row < size; row++) {
            const tr = document.createElement('tr');
            
            // Левый столбец - символы ключа
            const tdKey = document.createElement('td');
            tdKey.textContent = alphabet[row];
            tdKey.style.fontWeight = 'bold';
            tdKey.style.background = '#edf2f7';
            tr.appendChild(tdKey);
            
            // Ячейки с результатами шифрования
            for (let col = 0; col < size; col++) {
                const td = document.createElement('td');
                // По таблице Виженера: на пересечении строки (row) и столбца (col)
                // получаем символ со сдвигом (col + row) mod size
                const shiftedIndex = (col + row) % size;
                td.textContent = alphabet[shiftedIndex];
                
                // Добавляем data-атрибуты для подсветки
                td.dataset.row = row;
                td.dataset.col = col;
                td.dataset.char = alphabet[shiftedIndex];
                
                tr.appendChild(td);
            }
            tbody.appendChild(tr);
        }
        
        this.vigenereTableElement.appendChild(tbody);
        
        console.log('Таблица Виженера создана', { size, alphabet });
    }

    // Обработка загрузки файла
    handleFileUpload(event) {
        const file = event.target.files[0];
        if (!file) return;

        this.fileName.textContent = file.name;

        const reader = new FileReader();
        reader.onload = (e) => {
            this.inputText.value = e.target.result;
            this.updateStats();
            this.updateLanguageIndicator();
            this.showToast(`Файл "${file.name}" загружен`);
        };
        reader.onerror = () => {
            this.showToast('Ошибка при чтении файла', true);
        };
        reader.readAsText(file);
    }

    // Сохранение в файл
    saveToFile() {
        const text = this.outputText.value;
        if (!text) {
            this.showToast('Нет текста для сохранения!', true);
            return;
        }

        const algorithm = this.currentAlgorithm === 'vigenere' ? 'vigenere' : 'playfair';
        const date = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
        const filename = `${algorithm}_result_${date}.txt`;

        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);

        this.showToast(`Результат сохранен в файл "${filename}"`);
    }

    setAlgorithm(algorithm) {
        this.currentAlgorithm = algorithm;
        this.updateUI();
        this.updateStats();
        this.updateLanguageIndicator();
        this.clearAll();
        
        if (algorithm === 'playfair') {
            this.updateMatrixVisualization();
            this.encryptionExample.style.display = 'none';
        }
    }

    updateUI() {
        // Обновляем активные кнопки
        this.btnVigenere.classList.toggle('active', this.currentAlgorithm === 'vigenere');
        this.btnPlayfair.classList.toggle('active', this.currentAlgorithm === 'playfair');
        
        // Показываем/скрываем соответствующие поля
        this.vigenereKeys.style.display = this.currentAlgorithm === 'vigenere' ? 'block' : 'none';
        this.playfairKeys.style.display = this.currentAlgorithm === 'playfair' ? 'grid' : 'none';
        this.matrixVisualization.style.display = this.currentAlgorithm === 'playfair' ? 'grid' : 'none';
        this.vigenereTableSection.style.display = this.currentAlgorithm === 'vigenere' ? 'block' : 'none';
        
        // Обновляем визуализацию
        if (this.currentAlgorithm === 'playfair') {
            this.updateMatrixVisualization();
        }
    }

    // Переключение отображения таблицы Виженера
    toggleVigenereTable() {
        this.showVigenereTable = !this.showVigenereTable;
        this.vigenereTableContainer.classList.toggle('collapsed', !this.showVigenereTable);
        this.vigenereTableToggle.textContent = this.showVigenereTable ? '▼' : '▶';
    }

    // Подсветка ячеек в таблице Виженера для примера шифрования
    highlightVigenereCells(plaintext, key, ciphertext) {
        if (!this.vigenereTableElement) return;
        
        // Сначала убираем все подсветки
        const cells = this.vigenereTableElement.querySelectorAll('td');
        cells.forEach(cell => {
            cell.classList.remove('highlight-cell');
        });
        
        // Очищаем текст и ключ
        const cleanPlain = this.vigenere.cleanText(plaintext);
        const cleanKey = this.vigenere.cleanText(key);
        const preparedKey = this.vigenere.prepareKey(cleanPlain, cleanKey);
        
        // Подсвечиваем каждую использованную ячейку
        for (let i = 0; i < cleanPlain.length; i++) {
            const plainChar = cleanPlain[i];
            const keyChar = preparedKey[i];
            
            const plainIndex = this.vigenere.alphabet.indexOf(plainChar);
            const keyIndex = this.vigenere.alphabet.indexOf(keyChar);
            
            // Находим ячейку по data-атрибутам
            const targetCell = this.vigenereTableElement.querySelector(`td[data-row="${keyIndex}"][data-col="${plainIndex}"]`);
            if (targetCell) {
                targetCell.classList.add('highlight-cell');
            }
        }
        
        // Показываем пример шифрования
        this.showEncryptionExample(cleanPlain, preparedKey, ciphertext);
    }

    // Показ примера шифрования
    showEncryptionExample(plaintext, key, ciphertext) {
        this.encryptionExample.style.display = 'block';
        
        let html = '<div class="example-row">';
        html += '<span class="example-label">M:</span>';
        html += '<div class="example-text">';
        for (let char of plaintext) {
            html += `<span class="plain">${char}</span>`;
        }
        html += '</div></div>';
        
        html += '<div class="example-row">';
        html += '<span class="example-label">K:</span>';
        html += '<div class="example-text">';
        for (let char of key) {
            html += `<span class="key">${char}</span>`;
        }
        html += '</div></div>';
        
        html += '<div class="example-row">';
        html += '<span class="example-label">C:</span>';
        html += '<div class="example-text">';
        for (let char of ciphertext) {
            html += `<span class="cipher">${char}</span>`;
        }
        html += '</div></div>';
        
        this.exampleContent.innerHTML = html;
    }

    updateLanguageIndicator() {
        const text = this.inputText.value;
        let language = '';
        
        if (this.currentAlgorithm === 'vigenere') {
            language = 'Русский язык';
        } else {
            language = 'Английский язык';
        }
        
        // Добавляем информацию о наличии букв
        const hasRussian = this.vigenere.containsRussian(text);
        const hasEnglish = this.playfair.containsEnglish(text);
        
        if (this.currentAlgorithm === 'vigenere' && !hasRussian && text.length > 0) {
            language += ' ⚠️ нет русских букв';
        } else if (this.currentAlgorithm === 'playfair' && !hasEnglish && text.length > 0) {
            language += ' ⚠️ нет английских букв';
        }
        
        this.languageIndicator.textContent = language;
    }

    updateMatrixVisualization() {
        if (this.currentAlgorithm !== 'playfair') return;
        
        try {
            // Проверяем, существуют ли элементы
            if (!this.playfairKey1 || !this.playfairKey2 || !this.playfairKey3 || !this.playfairKey4) {
                console.error('Элементы ключей не найдены');
                return;
            }
            
            const key1 = this.playfairKey1.value || 'CRYPTO';
            const key2 = this.playfairKey2.value || 'GRAPHY';
            const key3 = this.playfairKey3.value || 'SECURE';
            const key4 = this.playfairKey4.value || 'MESSAGE';
            
            const matrices = this.playfair.getMatrices(key1, key2, key3, key4);
            
            // Отображаем каждую матрицу
            this.playfair.renderMatrix(matrices.M1, this.matrixElements.M1, key1);
            this.playfair.renderMatrix(matrices.M2, this.matrixElements.M2, key2);
            this.playfair.renderMatrix(matrices.M3, this.matrixElements.M3, key3);
            this.playfair.renderMatrix(matrices.M4, this.matrixElements.M4, key4);
        } catch (error) {
            console.error('Ошибка при визуализации матриц:', error);
        }
    }

    updateStats() {
        const inputTextValue = this.inputText.value;
        const keyCount = this.currentAlgorithm === 'vigenere' ? 1 : 4;
        
        this.textLength.innerHTML = inputTextValue.length + ' <span class="stat-unit">симв.</span>';
        this.keyCount.innerHTML = keyCount + ' <span class="stat-unit">' + 
            (keyCount === 1 ? 'ключ' : 'ключа') + '</span>';
        
        // Подсчет букв в зависимости от алгоритма
        let lettersOnlyValue = 0;
        if (this.currentAlgorithm === 'vigenere') {
            lettersOnlyValue = (inputTextValue.match(/[А-Яа-яЁё]/g) || []).length;
        } else {
            lettersOnlyValue = (inputTextValue.match(/[A-Za-z]/g) || []).length;
        }
        
        this.lettersOnly.innerHTML = lettersOnlyValue + ' <span class="stat-unit">букв</span>';
    }

    showToast(message, isError = false) {
        this.toastMessage.textContent = message;
        this.toast.className = 'toast' + (isError ? ' error' : '');
        this.toast.classList.add('show');
        
        setTimeout(() => {
            this.toast.classList.remove('show');
        }, 3000);
    }

    encrypt() {
        const inputTextValue = this.inputText.value;
        
        if (!inputTextValue) {
            this.showToast('Введите текст для шифрования!', true);
            return;
        }
        
        try {
            let result;
            
            if (this.currentAlgorithm === 'vigenere') {
                const key = this.vigenereKey.value;
                if (!key) {
                    this.showToast('Введите ключ шифрования!', true);
                    return;
                }
                // Проверка на русские буквы
                if (!this.vigenere.containsRussian(inputTextValue)) {
                    this.showToast('Предупреждение: текст не содержит русских букв!', true);
                }
                result = this.vigenere.encrypt(inputTextValue, key);
                
                // Подсвечиваем использованные ячейки в таблице
                this.highlightVigenereCells(inputTextValue, key, result);
            } else {
                const key1 = this.playfairKey1.value || 'CRYPTO';
                const key2 = this.playfairKey2.value || 'GRAPHY';
                const key3 = this.playfairKey3.value || 'SECURE';
                const key4 = this.playfairKey4.value || 'MESSAGE';
                
                // Проверка на английские буквы
                if (!this.playfair.containsEnglish(inputTextValue)) {
                    this.showToast('Предупреждение: текст не содержит английских букв!', true);
                }
                
                result = this.playfair.encrypt(inputTextValue, key1, key2, key3, key4);
            }
            
            this.outputText.value = result;
            this.showToast('Текст успешно зашифрован!');
            this.updateStats();
        } catch (error) {
            this.showToast('Ошибка при шифровании!', true);
            console.error(error);
        }
    }

    decrypt() {
        const inputTextValue = this.inputText.value;
        
        if (!inputTextValue) {
            this.showToast('Введите текст для дешифрования!', true);
            return;
        }
        
        try {
            let result;
            
            if (this.currentAlgorithm === 'vigenere') {
                const key = this.vigenereKey.value;
                if (!key) {
                    this.showToast('Введите ключ шифрования!', true);
                    return;
                }
                result = this.vigenere.decrypt(inputTextValue, key);
                
                // Для дешифрования тоже показываем пример, но с обратным процессом
                if (result) {
                    const cleanKey = this.vigenere.cleanText(key);
                    const preparedKey = this.vigenere.prepareKey(result, cleanKey);
                    this.highlightVigenereCells(result, key, inputTextValue);
                }
            } else {
                const key1 = this.playfairKey1.value || 'CRYPTO';
                const key2 = this.playfairKey2.value || 'GRAPHY';
                const key3 = this.playfairKey3.value || 'SECURE';
                const key4 = this.playfairKey4.value || 'MESSAGE';
                
                result = this.playfair.decrypt(inputTextValue, key1, key2, key3, key4);
            }
            
            this.outputText.value = result;
            this.showToast('Текст успешно расшифрован!');
            this.updateStats();
        } catch (error) {
            this.showToast('Ошибка при дешифровании!', true);
            console.error(error);
        }
    }

    clearAll() {
        this.inputText.value = '';
        this.outputText.value = '';
        this.vigenereKey.value = 'КЛЮЧ';
        this.playfairKey1.value = 'CRYPTO';
        this.playfairKey2.value = 'GRAPHY';
        this.playfairKey3.value = 'SECURE';
        this.playfairKey4.value = 'MESSAGE';
        this.fileName.textContent = 'Файл не выбран';
        this.fileInput.value = '';
        
        this.updateStats();
        this.updateLanguageIndicator();
        
        // Скрываем пример шифрования
        this.encryptionExample.style.display = 'none';
        
        // Убираем подсветку в таблице
        if (this.currentAlgorithm === 'vigenere' && this.vigenereTableElement) {
            const cells = this.vigenereTableElement.querySelectorAll('td');
            cells.forEach(cell => {
                cell.classList.remove('highlight-cell');
            });
        } else {
            this.updateMatrixVisualization();
        }
        
        this.showToast('Все поля очищены');
    }

    copyToClipboard() {
        if (!this.outputText.value) {
            this.showToast('Нет текста для копирования!', true);
            return;
        }
        
        this.outputText.select();
        this.outputText.setSelectionRange(0, 99999);
        
        try {
            document.execCommand('copy');
            this.showToast('Скопировано в буфер обмена!');
        } catch (err) {
            this.showToast('Ошибка при копировании!', true);
        }
    }
}

// Инициализация приложения после загрузки DOM
document.addEventListener('DOMContentLoaded', () => {
    // Создаем экземпляр приложения и делаем его глобально доступным
    window.app = new VigenereApp();
});