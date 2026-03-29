/**
 * LFSR: полином 23-й степени x^23 + x^5 + 1
 * Обратная связь по битам 23, 5 и 1 (нумерация от младшего бита, как в исходной схеме).
 */
const MAX_KEY_ENTER = 23;
const MASK_STATE = (1 << 23) - 1; // 23 младших бита — единицы (0x7fffff)

let plainTextBytes = null;
let generatedKey = null;
let cipherText = null;
let keyStart = 0;
let registerState = 0;

const $ = (id) => document.getElementById(id);

function outputInBinary(data) {
  if (!data || data.length === 0) return "";
  
  const lines = [];
  for (let i = 0; i < data.length; i++) {
    const binaryByte = data[i].toString(2).padStart(8, "0");
    lines.push(binaryByte);
    // каждые 10 байт — перенос строки для удобства чтения
    if ((i + 1) % 10 === 0 && i !== data.length - 1) {
      lines.push("\n");
    } else if ((i + 1) % 10 !== 0 && i !== data.length - 1) {
      lines.push(" ");
    }
  }
  return lines.join("");
}

function generateKey() {
  const len = plainTextBytes.length;
  generatedKey = new Uint8Array(len);
  registerState = keyStart >>> 0;

  for (let i = 0; i < len * 8; i++) {
    let xor = 0;
    xor ^= (registerState >> (23 - 1)) & 1;
    xor ^= (registerState >> (5 - 1)) & 1;
    xor ^= (registerState >> (1 - 1)) & 1;
    registerState = registerState << 1;
    const bit = (registerState >> 23) & 1;
    registerState = (registerState & MASK_STATE) | xor;
    const celoe = (i / 8) | 0;
    generatedKey[celoe] = ((generatedKey[celoe] << 1) | bit) & 0xff;
  }
}

function xorBuffers(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

function downloadBlob(data, filename) {
  const blob = new Blob([data], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function updateBitsLeft() {
  const el = $("keyInput");
  const len = el.value.replace(/\D/g, "").length;
  const left = Math.max(0, MAX_KEY_ENTER - len);
  $("lblEnterLeft").textContent =
    len >= MAX_KEY_ENTER
      ? "Ключ введён (23 бита)"
      : `Осталось ввести: ${left} бит`;
}

function setKeyError(msg) {
  $("label5").textContent = msg;
}

function bindUi() {
  $("fileInput").addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    $("rtxtboxGenerKey").textContent = "";
    $("rtxtboxCipherText").textContent = "";
    $("lblFile").textContent = "Текущий файл: ";
    $("lblCipher").textContent = "Полученное содержание файла";
    $("lblResKey").textContent = "Сгенерированный ключ";
    $("lblPlain").textContent = "Исходное содержимое файла";

    if (!file) return;

    const buf = await file.arrayBuffer();
    plainTextBytes = new Uint8Array(buf);

    $("rtxtboxPlainText").textContent = outputInBinary(plainTextBytes);
    $("lblPlain").textContent = `Исходное содержимое файла (${plainTextBytes.length} байт)`;

    $("keyInput").disabled = false;
    $("btnKeyEnter").disabled = false;
    $("keyInput").value = "";
    $("keyInput").maxLength = MAX_KEY_ENTER;
    updateBitsLeft();

    cipherText = new Uint8Array(plainTextBytes.length);
    $("lblFile").textContent = `Текущий файл:\n${file.name}`;
  });

  $("keyInput").addEventListener("input", () => {
    const only01 = $("keyInput").value.replace(/[^01]/g, "");
    if ($("keyInput").value !== only01) {
      $("keyInput").value = only01;
      setKeyError("В поле ключа можно вводить только 0 и 1!");
    } else {
      setKeyError("");
    }
    updateBitsLeft();
  });

  $("keyInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $("btnKeyEnter").click();
    }
  });

  $("btnKeyEnter").addEventListener("click", () => {
    const raw = $("keyInput").value.replace(/\r?\n/g, "");
    if (raw.length === 0) {
      alert("Вы не ввели значение ключа!");
      return;
    }

    setKeyError("");
    $("lblEnterLeft").textContent = "Ключ введён";

    let bits = raw;
    while (bits.length < MAX_KEY_ENTER) {
      bits += "0";
    }
    $("keyInput").value = bits.slice(0, MAX_KEY_ENTER);

    keyStart = parseInt($("keyInput").value, 2) >>> 0;
    $("btnEncipher").disabled = false;
    $("btnDecipher").disabled = false;
  });

  $("btnEncipher").addEventListener("click", () => {
    if (!plainTextBytes) return;
    setKeyError("");
    generateKey();
    $("rtxtboxGenerKey").textContent = outputInBinary(generatedKey);
    cipherText = xorBuffers(generatedKey, plainTextBytes);
    $("rtxtboxCipherText").textContent = outputInBinary(cipherText);
    $("lblResKey").textContent = `Сгенерированный ключ (${generatedKey.length} байт)`;
    $("lblCipher").textContent = `Полученное содержание файла (${cipherText.length} байт)`;
    downloadBlob(cipherText, "enciphered.bin");
    alert("Файл зашифрован! Сохранён как enciphered.bin");
  });

  $("btnDecipher").addEventListener("click", () => {
    if (!plainTextBytes) return;
    setKeyError("");
    generateKey();
    $("rtxtboxGenerKey").textContent = outputInBinary(generatedKey);
    cipherText = xorBuffers(generatedKey, plainTextBytes);
    $("rtxtboxCipherText").textContent = outputInBinary(cipherText);
    $("lblResKey").textContent = `Сгенерированный ключ (${generatedKey.length} байт)`;
    $("lblCipher").textContent = `Полученное содержание файла (${cipherText.length} байт)`;
    downloadBlob(cipherText, "deciphered.bin");
    alert("Файл расшифрован! Сохранён как deciphered.bin");
  });

  $("btnClear").addEventListener("click", () => {
    $("lblEnterLeft").textContent = "Осталось ввести: 23 бита";
    $("keyInput").value = "";
    $("rtxtboxCipherText").textContent = "";
    $("rtxtboxGenerKey").textContent = "";
    $("rtxtboxPlainText").textContent = "";
    $("btnKeyEnter").disabled = true;
    $("keyInput").disabled = true;
    $("btnEncipher").disabled = true;
    $("btnDecipher").disabled = true;
    $("lblCipher").textContent = "Полученное содержание файла";
    $("lblResKey").textContent = "Сгенерированный ключ";
    $("lblPlain").textContent = "Исходное содержимое файла";
    $("lblFile").textContent = "Текущий файл: —";
    $("fileInput").value = "";
    setKeyError("");
    plainTextBytes = null;
    generatedKey = null;
    cipherText = null;
  });
}

bindUi();