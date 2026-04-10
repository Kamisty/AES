using System;
using System.Data;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace AESAnalyzer
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

            textBox1.Multiline = true;           // Многострочный режим
            textBox1.ScrollBars = ScrollBars.Vertical; // Вертикальный скроллбар
            textBox1.ReadOnly = true;            // Только для чтения
            textBox1.WordWrap = false;           // Без переноса слов (опционально)

            text2.Multiline = true;           // Многострочный режим
            text2.ScrollBars = ScrollBars.Vertical; // Вертикальный скроллбар
            text2.ReadOnly = true;            // Только для чтения
            text2.WordWrap = false;           // Без переноса слов (опционально)

            lavina.Multiline = true;           // Многострочный режим
            lavina.ScrollBars = ScrollBars.Vertical; // Вертикальный скроллбар
            lavina.ReadOnly = true;            // Только для чтения
            lavina.WordWrap = false;           // Без переноса слов (опционально)


            proisv.Multiline = true;           // Многострочный режим
            proisv.ScrollBars = ScrollBars.Vertical; // Вертикальный скроллбар
            proisv.ReadOnly = true;            // Только для чтения
            proisv.WordWrap = false;           // Без переноса слов (опционально)


        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {

        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {

        }
        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                int keySize = GetSelectedKeySize();
                byte[] generatedKey = GenerateAESKeyManual(keySize);

                // РАЗНЫЕ форматы:
                string hexKey = BitConverter.ToString(generatedKey).Replace("-", ""); // HEX
                string decimalKey = string.Join(" ", generatedKey); // Десятичные

                key.Text = $"{decimalKey}";
                key2.Text = $"{hexKey}";

                AddToResults($"Ключ {keySize} бит = {generatedKey.Length} байт");
                AddToResults($"Байты: {decimalKey}");
                AddToResults($"HEX: {hexKey}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка",
                              MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

        }

        // Получение выбранного размера ключа
        private int GetSelectedKeySize()
        {
            if (radio128.Checked)
                return 128;
            else if (radio192.Checked)
                return 192;
            else if (radio256.Checked)
                return 256;
            else
                return 128; // По умолчанию
        }

        // Генерация ключа AES
        private byte[] GenerateAESKeyManual(int keySize)
        {
            // 1. Определяем размер ключа в байтах
            int keySizeBytes = keySize / 8; // 128 бит = 16 байт, 192 = 24, 256 = 32

            // 2. Создаем массив для ключа
            byte[] key = new byte[keySizeBytes];

            // 3. Используем криптографический генератор случайных чисел
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            return key;
        }

        // Добавление сообщения в ListBox
        private void AddToResults(string message)
        {
            textBox1.AppendText(message + Environment.NewLine);
            textBox1.ScrollToCaret();
        }

        private void AddToResults1(string message)
        {
            lavina.AppendText(message + Environment.NewLine);
            textBox1.ScrollToCaret();
        }
        private byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("-", "").Replace(" ", "");
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];

            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }
        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                textBox1.Clear();
                AddToResults("НАЧАЛО АНАЛИЗА AES");

                // Проверка наличия текста
                if (string.IsNullOrEmpty(text.Text))
                {
                    AddToResults("Ошибка: Введите текст для шифрования");
                    return;
                }

                // Проверка наличия ключа
                if (key2.Text == "ЗДЕСЬ ПОЯВИТСЯ КЛЮЧ" || string.IsNullOrEmpty(key2.Text))
                {
                    AddToResults("Ошибка: Сначала сгенерируйте ключ");
                    return;
                }

                string inputText = text.Text;

                // Анализ исходного текста
                AddToResults("ИСХОДНЫЙ ТЕКСТ");
                AddToResults($"Текст: {inputText}");
                AddToResults($"Длина текста: {inputText.Length} символов");
                AddToResults($"Размер в байтах: {Encoding.UTF8.GetByteCount(inputText)}");
                AddToResults($"");

                // Анализ ключа
                AddToResults("\nКЛЮЧ");
                byte[] keyBytes = HexStringToByteArray(key2.Text);
                int selectedKeySize = GetSelectedKeySize();

                // Проверка соответствия размера ключа
                int expectedKeyLength = selectedKeySize / 8;
                if (keyBytes.Length != expectedKeyLength)
                {
                    AddToResults($"ОШИБКА: Размер ключа не соответствует выбранному алгоритму!");
                    AddToResults($"Выбрано: AES-{selectedKeySize} (требуется {expectedKeyLength} байт)");
                    AddToResults($"Получено: {keyBytes.Length} байт");
                    AddToResults($"Проверьте выбор размера ключа!");
                    return;
                }

                AddToResults($"Размер ключа: {selectedKeySize} бит");
                AddToResults($"Длина ключа: {keyBytes.Length} байт");
                AddToResults($"Ключ (HEX): {key2.Text}");
                AddToResults($"");

                // Генерируем IV (вектор инициализации)
                byte[] iv;
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = selectedKeySize;
                    aes.GenerateIV();
                    iv = aes.IV;
                }

                AddToResults($"IV (HEX): {BitConverter.ToString(iv).Replace("-", "")}");
                AddToResults($"IV (Base64): {Convert.ToBase64String(iv)}");
                AddToResults($"");
                IV.Text = BitConverter.ToString(iv).Replace("-", "");

                // Используем ручную реализацию:
                ManualAES manualAES = new ManualAES();
                byte[] encryptedBytes = manualAES.EncryptTextManual(
                    text: inputText,
                    hexKey: key2.Text,
                    iv: iv,
                    selectedKeySize: selectedKeySize
                );

                // ========== ПРОВЕРКА С СИСТЕМНОЙ РЕАЛИЗАЦИЕЙ ==========
                AddToResults("\nПРОВЕРКА КОРРЕКТНОСТИ");

                // Системное шифрование AES с теми же параметрами
                byte[] systemEncrypted;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = keyBytes;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(inputText);
                        systemEncrypted = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    }
                }

                // Сравнение результатов
                bool isCorrect = encryptedBytes.SequenceEqual(systemEncrypted);

                if (isCorrect)
                {
                    AddToResults("Ручная реализация AES работает КОРРЕКТНО!");
                    AddToResults("Результат совпадает с System.Security.Cryptography.Aes");
                }
                else
                {
                    AddToResults("ОШИБКА: Результаты НЕ совпадают!");
                    AddToResults("Ваша реализация AES дает другой результат");

                    // Поиск первого расхождения
                    for (int i = 0; i < Math.Min(encryptedBytes.Length, systemEncrypted.Length); i++)
                    {
                        if (encryptedBytes[i] != systemEncrypted[i])
                        {
                            AddToResults($"Первое расхождение на позиции {i}:");
                            AddToResults($"  Ваш байт: {encryptedBytes[i]:X2} ({encryptedBytes[i]})");
                            AddToResults($"  Системный: {systemEncrypted[i]:X2} ({systemEncrypted[i]})");
                            break;
                        }
                    }
                }
                AddToResults($"");
                // ========== КОНЕЦ ПРОВЕРКИ ==========

                // Преобразуем зашифрованные байты в Base64 для отображения
                string encryptedBase64 = Convert.ToBase64String(encryptedBytes);

                // Преобразуем в HEX для отображения
                string encryptedHex = BitConverter.ToString(encryptedBytes).Replace("-", "");

                // Анализ зашифрованного текста
                AddToResults("\nЗАШИФРОВАННЫЙ ТЕКСТ");
                AddToResults($"Размер зашифрованных данных: {encryptedBytes.Length} байт");
                AddToResults($"Зашифрованный текст (Base64): {encryptedBase64}");
                AddToResults($"Зашифрованный текст (HEX): {encryptedHex}");
                AddToResults($"");
                text2.Text = encryptedBase64;

                // Сводная информация
                AddToResults("\nСВОДНАЯ ИНФОРМАЦИЯ");
                AddToResults($"Алгоритм: AES-{selectedKeySize}");
                AddToResults($"Режим: CBC");
                AddToResults($"Размер исходного текста: {Encoding.UTF8.GetByteCount(inputText)} байт");
                AddToResults($"Размер зашифрованного текста: {encryptedBytes.Length} байт");
                AddToResults($"Размер ключа: {keyBytes.Length} байт ({selectedKeySize} бит)");
                AddToResults($"Размер IV: {iv.Length} байт (128 бит)");
                AddToResults($"Количество блоков: {encryptedBytes.Length / 16}");

                // Дополнительная информация для проверки
                if (isCorrect)
                {
                    AddToResults($"Корректность: ВЕРНО");
                }
                else
                {
                    AddToResults($"Корректность:ОШИБКА");
                    AddToResults($"Системный результат (Base64): {Convert.ToBase64String(systemEncrypted)}");
                }
            }
            catch (FormatException)
            {
                AddToResults("Ошибка: Неверный формат ключа (используйте HEX формат)");
            }
            catch (ArgumentException ex)
            {
                AddToResults($"Ошибка аргумента: {ex.Message}");
            }
            catch (CryptographicException ex)
            {
                AddToResults($"Ошибка шифрования: {ex.Message}");
            }
            catch (Exception ex)
            {
                AddToResults($"Неожиданная ошибка: {ex.Message}");
            }


        }



        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void key2_TextChanged(object sender, EventArgs e)
        {

        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void tabPage1_Click(object sender, EventArgs e)
        {

        }

        private void button3_Click(object sender, EventArgs e)
        {
            try
            {
                textBox1.Clear();
                AddToResults("НАЧАЛО ДЕШИФРОВАНИЯ AES");

                // Проверка наличия зашифрованного текста
                if (string.IsNullOrEmpty(text2.Text))
                {
                    AddToResults("Ошибка: Нет зашифрованного текста для дешифрования");
                    return;
                }

                // Проверка наличия ключа
                if (key2.Text == "ЗДЕСЬ ПОЯВИТСЯ КЛЮЧ" || string.IsNullOrEmpty(key2.Text))
                {
                    AddToResults("Ошибка: Сначала сгенерируйте ключ");
                    return;
                }

                // Проверка наличия IV
                if (string.IsNullOrEmpty(IV.Text))
                {
                    AddToResults("Ошибка: Не найден IV (вектор инициализации)");
                    return;
                }

                // Получаем параметры
                string ciphertextBase64 = text2.Text;
                string keyHex = key2.Text;
                string ivHex = IV.Text;
                int keySize = GetSelectedKeySize();

                // Анализ перед дешифрованием
                AddToResults("\nАНАЛИЗ ПЕРЕД ДЕШИФРОВАНИЕМ:");
                AddToResults($"Алгоритм: AES-{keySize}");
                AddToResults($"Размер ключа: {keySize} бит");
                AddToResults($"Ключ (HEX): {keyHex}");
                AddToResults($"IV (HEX): {ivHex}");
                AddToResults($"Зашифрованный текст (Base64): {ciphertextBase64}");
                AddToResults("");
                // Создаем объект дешифратора
                ManualAESDecryptor decryptor = new ManualAESDecryptor();

                // Дешифруем с помощью ручной реализации

                string decryptedText = decryptor.DecryptFromBase64(ciphertextBase64, keyHex, ivHex, keySize);

                AddToResults($"\nРАСШИФРОВАННЫЙ ТЕКСТ:");
                AddToResults($"Текст: {decryptedText}");
                AddToResults($"Длина: {decryptedText.Length} символов");
                AddToResults($"Размер в байтах: {Encoding.UTF8.GetByteCount(decryptedText)}");
                AddToResults("");
                // Проверка с системной реализацией
                AddToResults("\nПРОВЕРКА СИСТЕМНОЙ РЕАЛИЗАЦИЕЙ");

                try
                {
                    // Системное дешифрование
                    byte[] ciphertextBytes = Convert.FromBase64String(ciphertextBase64);
                    byte[] keyBytes = HexStringToByteArray(keyHex);
                    byte[] ivBytes = HexStringToByteArray(ivHex);

                    string systemDecryptedText;
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = keyBytes;
                        aes.IV = ivBytes;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;

                        using (ICryptoTransform decryptorSys = aes.CreateDecryptor())
                        {
                            byte[] decryptedBytes = decryptorSys.TransformFinalBlock(ciphertextBytes, 0, ciphertextBytes.Length);
                            systemDecryptedText = Encoding.UTF8.GetString(decryptedBytes);
                        }
                    }

                    // Сравнение
                    if (decryptedText == systemDecryptedText)
                    {

                        AddToResults("Результаты совпадают с системной реализацией");
                        AddToResults($"Ручная реализация: {decryptedText}");
                        AddToResults($"Системная реализация: {systemDecryptedText}");
                        AddToResults("");
                    }
                    else
                    {
                        AddToResults("ОШИБКА: Результаты НЕ совпадают!");
                        AddToResults($"Ручная реализация: {decryptedText}");
                        AddToResults($"Системная реализация: {systemDecryptedText}");
                        AddToResults("");
                    }
                }
                catch (Exception ex)
                {
                    AddToResults($"Ошибка при проверке системной реализацией: {ex.Message}");
                }

                // Сравнение с исходным текстом (если есть)
                if (!string.IsNullOrEmpty(text.Text))
                {
                    AddToResults("\nСРАВНЕНИЕ С ИСХОДНЫМ ТЕКСТОМ ");

                    if (decryptedText == text.Text)
                    {
                        AddToResults("Расшифрованный текст совпадает с исходным!");
                        AddToResults($"Оригинал: {text.Text}");
                        AddToResults($"Расшифровано: {decryptedText}");
                    }
                    else
                    {
                        AddToResults("ОШИБКА: Расшифрованный текст НЕ совпадает с исходным!");
                        AddToResults($"Оригинал: {text.Text}");
                        AddToResults($"Расшифровано: {decryptedText}");
                    }
                }




                byte[] cipherBytes = Convert.FromBase64String(ciphertextBase64);
                byte[] keyBytesDebug = HexStringToByteArray(keyHex);
                byte[] ivBytesDebug = HexStringToByteArray(ivHex);

                List<string> steps = decryptor.StepByStepDecryption(cipherBytes, keyBytesDebug, ivBytesDebug, keySize);
                foreach (string step in steps)
                {
                    AddToResults(step);
                }
            }
            catch (FormatException)
            {
                AddToResults("Ошибка: Неверный формат данных (используйте Base64 для зашифрованного текста и HEX для ключа/IV)");
            }
            catch (ArgumentException ex)
            {
                AddToResults($"Ошибка аргумента: {ex.Message}");
            }
            catch (CryptographicException ex)
            {
                AddToResults($"Ошибка дешифрования: {ex.Message}");
            }
            catch (Exception ex)
            {
                AddToResults($"Неожиданная ошибка: {ex.Message}");
            }
        }

        private void textBox3_TextChanged(object sender, EventArgs e)
        {

        }

        private void button4_Click(object sender, EventArgs e) // Эффект лавины
        {
            lavina.Clear();
            try
            {
                
                AddToResults1("АНАЛИЗ ЭФФЕКТА ЛАВИНЫ");

                // Проверка наличия данных
                if (string.IsNullOrEmpty(text.Text))
                {
                    AddToResults1("Ошибка: Введите текст для анализа");
                    return;
                }

                if (key2.Text == "ЗДЕСЬ ПОЯВИТСЯ КЛЮЧ" || string.IsNullOrEmpty(key2.Text))
                {
                    AddToResults1("Ошибка: Сначала сгенерируйте ключ");
                    return;
                }

                if (string.IsNullOrEmpty(IV.Text))
                {
                    AddToResults1("Ошибка: Нет IV. Сначала выполните шифрование");
                    return;
                }

                // Получаем параметры (ВСЕ КАК СТРОКИ!)
                string originalText = text.Text;
                string keyHex = key2.Text;        // ← строка HEX
                string ivHex = IV.Text;           // ← строка HEX
                int keySize = GetSelectedKeySize();

                // Преобразуем IV из HEX строки в байты
                byte[] ivBytes = HexStringToByteArray(ivHex);

                AddToResults1($"\nПАРАМЕТРЫ:");
                AddToResults1($"Текст: '{originalText}'");
                AddToResults1($"Длина: {originalText.Length} символов");
                AddToResults1($"Ключ (HEX): {keyHex}");
                AddToResults1($"IV (HEX): {ivHex}");
                AddToResults1($"Размер ключа: {keySize} бит");
                AddToResults1("");
                // Создаем объект AES
                ManualAES aes = new ManualAES();

                // Шифруем оригинальный текст (ПЕРЕДАЕМ СТРОКУ keyHex!)
                byte[] originalEncrypted = aes.EncryptTextManual(
                    text: originalText,
                    hexKey: keyHex,      // ← строка HEX
                    iv: ivBytes,         // ← байты
                    selectedKeySize: keySize
                );

                AddToResults1($"\nТЕСТ 1: Изменение 1 символа в тексте");

                // Меняем первый символ текста
                if (originalText.Length > 0)
                {
                    // Изменяем первый символ
                    char firstChar = originalText[0];
                    char modifiedChar = (char)(firstChar + 1);
                    string modifiedText = modifiedChar + originalText.Substring(1);

                    AddToResults1($"Оригинальный текст: '{originalText}'");
                    AddToResults1($"Измененный текст: '{modifiedText}'");
                    AddToResults1($"Изменен 1 символ (первый)");
                   
                    // Шифруем измененный текст
                    byte[] modifiedEncrypted = aes.EncryptTextManual(
                        text: modifiedText,
                        hexKey: keyHex,      // ← строка HEX
                        iv: ivBytes,         // ← байты  
                        selectedKeySize: keySize
                    );

                    // Сравниваем
                    CompareResults(originalEncrypted, modifiedEncrypted, "изменение текста");
                    AddToResults1("");
                }

                AddToResults1($"\nТЕСТ 2: Изменение 1 байта в ключе");

                // Меняем один байт в ключе
                byte[] keyBytes = HexStringToByteArray(keyHex);
                if (keyBytes.Length > 0)
                {
                    byte[] modifiedKeyBytes = new byte[keyBytes.Length];
                    Array.Copy(keyBytes, modifiedKeyBytes, keyBytes.Length);
                    modifiedKeyBytes[0] ^= 0x01; // Изменяем один бит

                    // Преобразуем обратно в HEX строку
                    string modifiedKeyHex = BitConverter.ToString(modifiedKeyBytes).Replace("-", "");

                    AddToResults1($"Оригинальный ключ: {keyHex}");
                    AddToResults1($"Измененный ключ: {modifiedKeyHex}");
                    AddToResults1($"Изменен 1 бит в первом байте ключа");
                    
                    // Шифруем с измененным ключом
                    byte[] keyModifiedEncrypted = aes.EncryptTextManual(
                        text: originalText,
                        hexKey: modifiedKeyHex,  // ← новая HEX строка ключа
                        iv: ivBytes,             // ← байты
                        selectedKeySize: keySize
                    );

                    // Сравниваем
                    CompareResults(originalEncrypted, keyModifiedEncrypted, "изменение ключа");
                    AddToResults1("");
                }

                AddToResults1($"\nТЕСТ 3: Изменение 1 байта в IV");

                // Меняем один байт в IV
                if (ivBytes.Length > 0)
                {
                    byte[] modifiedIVBytes = new byte[ivBytes.Length];
                    Array.Copy(ivBytes, modifiedIVBytes, ivBytes.Length);
                    modifiedIVBytes[0] ^= 0x01; // Изменяем один бит

                    // Преобразуем обратно в HEX строку для отображения
                    string modifiedIVHex = BitConverter.ToString(modifiedIVBytes).Replace("-", "");

                    AddToResults1($"Оригинальный IV: {ivHex}");
                    AddToResults1($"Измененный IV: {modifiedIVHex}");
                    AddToResults1($"Изменен 1 бит в первом байте IV");
                    AddToResults1("");
                    // Шифруем с измененным IV
                    byte[] ivModifiedEncrypted = aes.EncryptTextManual(
                        text: originalText,
                        hexKey: keyHex,          // ← строка HEX ключа
                        iv: modifiedIVBytes,     // ← новые байты IV
                        selectedKeySize: keySize
                    );

                    // Сравниваем
                    CompareResults(originalEncrypted, ivModifiedEncrypted, "изменение IV");
                }

                AddToResults1($"\nВЫВОД");
                AddToResults1($"Эффект лавины показывает, как малое изменение во входных данных");
                AddToResults1($"приводит к значительным изменениям в выходных данных.");
                
            }
            catch (Exception ex)
            {
                AddToResults1($"Ошибка: {ex.Message}");
            }
            AddToResults1("");
        }

        // Метод для сравнения двух зашифрованных результатов
        private void CompareResults(byte[] original, byte[] modified, string testName)
        {
            int totalBits = original.Length * 8;
            int changedBits = 0;
            int changedBytes = 0;

            // Сравниваем байт за байтом
            for (int i = 0; i < Math.Min(original.Length, modified.Length); i++)
            {
                if (original[i] != modified[i])
                {
                    changedBytes++;

                    // Считаем измененные биты
                    byte xor = (byte)(original[i] ^ modified[i]);
                    changedBits += CountBits(xor);
                }
            }

            // Расчет процента изменений
            double percentage = (double)changedBits / totalBits * 100;

            // Вывод результатов
            AddToResults1($"Результат ({testName}):");
            AddToResults1($"Изменено байт: {changedBytes} из {original.Length} ({changedBytes * 100.0 / original.Length:F1}%)");
            AddToResults1($"Изменено бит: {changedBits} из {totalBits} ({percentage:F2}%)");

            // Оценка
            string quality = percentage switch
            {
                >= 45 and <= 55 => "ОТЛИЧНЫЙ эффект лавины",
                >= 40 and <= 60 => "ХОРОШИЙ эффект лавины",
                >= 35 and <= 65 => "УДОВЛЕТВОРИТЕЛЬНЫЙ",
                _ => "!!! СЛАБЫЙ эффект лавины"
            };

            AddToResults1($"Оценка: {quality}");
        }

        // Метод для подсчета битов
        private int CountBits(byte value)
        {
            int count = 0;
            while (value != 0)
            {
                count++;
                value &= (byte)(value - 1);
            }
            return count;
        }

        private void tabPage3_Click(object sender, EventArgs e)
        {

        }

        private void button5_Click(object sender, EventArgs e)
        {
            proisv.Clear();
            try
            {
                textBox1.Clear();
                AddToResults2("АНАЛИЗ РАСПРЕДЕЛЕНИЯ БАЙТОВ");

                if (string.IsNullOrEmpty(text.Text))
                {
                    AddToResults2("Ошибка: Введите текст для анализа");
                    return;
                }

                string inputText = text.Text;
                byte[] inputBytes = Encoding.UTF8.GetBytes(inputText);
                AddToResults2("");
                AddToResults2($"\nИСХОДНЫЕ ДАННЫЕ:");
                AddToResults2($"Текст: {text.Text} ");
                AddToResults2($"Длина: {inputText.Length} символов");
                AddToResults2($"Размер: {inputBytes.Length} байт");
                AddToResults2("");
                // Анализ исходного текста
                AddToResults2($"\nРАСПРЕДЕЛЕНИЕ В ИСХОДНОМ ТЕКСТЕ");
                AnalyzeByteDistribution(inputBytes, "Исходный текст");

                // Шифруем для анализа
                if (!string.IsNullOrEmpty(key2.Text) && key2.Text != "ЗДЕСЬ ПОЯВИТСЯ КЛЮЧ")
                {
                    ManualAES aes = new ManualAES();
                    int keySize = GetSelectedKeySize();

                    // Создаем IV если нет
                    byte[] iv;
                    if (string.IsNullOrEmpty(IV.Text) || IV.Text == "IV появится после шифрования")
                    {
                        using (Aes aesSys = Aes.Create())
                        {
                            aesSys.KeySize = keySize;
                            aesSys.GenerateIV();
                            iv = aesSys.IV;
                            IV.Text = BitConverter.ToString(iv).Replace("-", "");
                        }
                    }
                    else
                    {
                        iv = HexStringToByteArray(IV.Text);
                    }

                    byte[] encryptedBytes = aes.EncryptTextManual(inputText, key2.Text, iv, keySize);
                    AddToResults2("");
                    AddToResults2($"\nРАСПРЕДЕЛЕНИЕ В ЗАШИФРОВАННОМ ТЕКСТЕ ");
                    AnalyzeByteDistribution(encryptedBytes, "Зашифрованный текст");
                    AddToResults2("");
                    // Гистограмма
                    AddToResults2($"\nГИСТОГРАММА РАСПРЕДЕЛЕНИЯ");
                    ShowByteHistogram(encryptedBytes);
                }
            }
            catch (Exception ex)
            {
                AddToResults2($"Ошибка: {ex.Message}");
            }
        }
        private void AnalyzeByteDistribution(byte[] data, string name)
        {
            int[] frequency = new int[256];

            // Считаем частоту каждого байта
            foreach (byte b in data)
            {
                frequency[b]++;
            }

            // Основная статистика
            int totalBytes = data.Length;
            int uniqueBytes = frequency.Count(f => f > 0);
            double entropy = CalculateEntropy(frequency, totalBytes);

            AddToResults2($"Всего байт: {totalBytes}");
            AddToResults2($"Уникальных байт: {uniqueBytes} ({(uniqueBytes * 100.0 / 256):F1}% от 256)");
            AddToResults2($"Энтропия: {entropy:F4} бит/байт");
            AddToResults2($"Максимальная энтропия: 8.0 бит/байт");

            // Наиболее частые байты
            AddToResults2($"\nСамые частые байты:");
            var topBytes = frequency.Select((f, i) => new { Byte = i, Count = f })
                                   .Where(x => x.Count > 0)
                                   .OrderByDescending(x => x.Count)
                                   .Take(5);

            foreach (var item in topBytes)
            {
                double percentage = item.Count * 100.0 / totalBytes;
                AddToResults2($"  {item.Byte:X2}h ({item.Byte:D3}): {item.Count} раз ({percentage:F2}%)");
            }

            // Равномерность распределения
            double uniformity = CalculateUniformity(frequency, totalBytes);
            AddToResults2($"\nРавномерность распределения: {uniformity:F2}%");

            if (uniformity > 85)
                AddToResults2($"Отличное равномерное распределение");
            else if (uniformity > 70)
                AddToResults2($"Хорошее распределение");
            else if (uniformity > 60)
                AddToResults2($" Удовлетворительное распределение");
            else
                AddToResults2($"Неравномерное распределение");
        }

        private double CalculateEntropy(int[] frequency, int total)
        {
            double entropy = 0;

            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                {
                    double probability = frequency[i] / (double)total;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }

        private double CalculateUniformity(int[] frequency, int total)
        {
            if (total == 0) return 0;

            double expected = total / 256.0;
            double sumSquaredDiff = 0;

            for (int i = 0; i < 256; i++)
            {
                double diff = frequency[i] - expected;
                sumSquaredDiff += diff * diff;
            }

            double chiSquared = sumSquaredDiff / expected;
            // Простая оценка равномерности (0-100%)
            return Math.Max(0, 100 - (chiSquared / 10));
        }

        private void ShowByteHistogram(byte[] data)
        {
            int[] frequency = new int[256];
            foreach (byte b in data)
            {
                frequency[b]++;
            }

            // Находим максимальную частоту для масштабирования
            int maxFreq = frequency.Max();
            int scale = Math.Max(1, maxFreq / 20); // масштаб для отображения

            AddToResults2("Гистограмма (каждые 16 байт):");

            for (int row = 0; row < 16; row++)
            {
                string line = $"{row * 16:X3}-{(row * 16 + 15):X3}: ";

                for (int col = 0; col < 16; col++)
                {
                    int byteValue = row * 16 + col;
                    int freq = frequency[byteValue];
                    int bars = (int)Math.Round(freq / (double)scale);

                    if (bars > 0)
                        line += new string('█', Math.Min(bars, 10));
                    else if (freq > 0)
                        line += "▏";
                    else
                        line += " ";
                }

                AddToResults2(line);
            }

            AddToResults2($"Масштаб: 1 символ = {scale} вхождений");
            AddToResults2($"█ - байт встречается, пробел - не встречается");
        }
        private void AddToResults2(string message)
        {
            proisv.AppendText(message + Environment.NewLine);
            proisv.ScrollToCaret();
        }

        private void button6_Click(object sender, EventArgs e)
        {

        }
    }
}


