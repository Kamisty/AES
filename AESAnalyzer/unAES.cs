
namespace AESAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;

    public class ManualAESDecryptor
    {
        // S-box для обратного преобразования
        private static readonly byte[] InvSBox = new byte[]
        {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        };

        // Rcon для обратного преобразования ключей
        private static readonly byte[] Rcon = new byte[]
        {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
        };

        // Таблицы для Inverse MixColumns
        private static readonly byte[,] InvMixColumnsMatrix = new byte[,]
        {
        { 0x0E, 0x0B, 0x0D, 0x09 },
        { 0x09, 0x0E, 0x0B, 0x0D },
        { 0x0D, 0x09, 0x0E, 0x0B },
        { 0x0B, 0x0D, 0x09, 0x0E }
        };

        // Основной метод дешифрования
        public byte[] DecryptManual(byte[] ciphertext, byte[] key, byte[] iv, int keySize = 128)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw new ArgumentException("Ciphertext is empty");

            if (key == null)
                throw new ArgumentException("Key is null");

            if (iv == null || iv.Length != 16)
                throw new ArgumentException("IV must be 16 bytes");

            // Проверяем размер ключа
            int keyBytes = keySize / 8;
            if (key.Length != keyBytes)
                throw new ArgumentException($"Key must be {keyBytes} bytes for AES-{keySize}");

            // Определяем количество раундов
            int rounds = keySize switch
            {
                128 => 10,
                192 => 12,
                256 => 14,
                _ => 10
            };

            // Генерируем расписание ключей
            byte[][] roundKeys = KeyExpansion(key, rounds);

            // Режим CBC: сначала XOR с IV
            byte[] previousBlock = iv;
            List<byte> plaintext = new List<byte>();

            // Обрабатываем по блокам
            for (int block = 0; block < ciphertext.Length; block += 16)
            {
                byte[] currentBlock = new byte[16];
                Array.Copy(ciphertext, block, currentBlock, 0, Math.Min(16, ciphertext.Length - block));

                // Дешифруем блок
                byte[] decryptedBlock = DecryptBlock(currentBlock, roundKeys, rounds);

                // CBC: XOR с предыдущим зашифрованным блоком
                for (int i = 0; i < 16; i++)
                {
                    decryptedBlock[i] ^= previousBlock[i];
                }

                // Сохраняем для следующего блока
                previousBlock = currentBlock;

                plaintext.AddRange(decryptedBlock);
            }

            // Удаляем padding PKCS7
            return RemovePadding(plaintext.ToArray());
        }

        // Дешифрование одного блока
        private byte[] DecryptBlock(byte[] block, byte[][] roundKeys, int rounds)
        {
            byte[] state = new byte[16];
            Array.Copy(block, state, 16);

            // Начальный раунд: AddRoundKey с последним ключом
            AddRoundKey(state, roundKeys[rounds]);

            // Основные раунды
            for (int round = rounds - 1; round > 0; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, roundKeys[round]);
                InvMixColumns(state);
            }

            // Финальный раунд
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, roundKeys[0]);

            return state;
        }

        // Inverse SubBytes - замена байтов через обратный S-box
        private void InvSubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] = InvSBox[state[i]];
            }
        }

        // Inverse ShiftRows - циклический сдвиг строк в обратную сторону
        private void InvShiftRows(byte[] state)
        {
            // Сохраняем временную копию
            byte[] temp = new byte[16];
            Array.Copy(state, temp, 16);

            // Первая строка не сдвигается
            state[0] = temp[0];
            state[4] = temp[4];
            state[8] = temp[8];
            state[12] = temp[12];

            // Вторая строка: сдвиг на 1 байт вправо
            state[1] = temp[13];
            state[5] = temp[1];
            state[9] = temp[5];
            state[13] = temp[9];

            // Третья строка: сдвиг на 2 байта вправо
            state[2] = temp[10];
            state[6] = temp[14];
            state[10] = temp[2];
            state[14] = temp[6];

            // Четвертая строка: сдвиг на 3 байта вправо
            state[3] = temp[7];
            state[7] = temp[11];
            state[11] = temp[15];
            state[15] = temp[3];
        }

        // Inverse MixColumns - обратное смешивание столбцов
        private void InvMixColumns(byte[] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte[] column = new byte[4];
                for (int j = 0; j < 4; j++)
                {
                    column[j] = state[i * 4 + j];
                }

                // Применяем обратное преобразование MixColumns
                byte[] result = new byte[4];
                for (int row = 0; row < 4; row++)
                {
                    byte sum = 0;
                    for (int col = 0; col < 4; col++)
                    {
                        sum ^= GFMul(InvMixColumnsMatrix[row, col], column[col]);
                    }
                    result[row] = sum;
                }

                // Копируем обратно в state
                for (int j = 0; j < 4; j++)
                {
                    state[i * 4 + j] = result[j];
                }
            }
        }

        // Умножение в поле Галуа GF(2^8)
        private byte GFMul(byte a, byte b)
        {
            byte result = 0;
            byte hiBitSet;

            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) == 1)
                    result ^= a;

                hiBitSet = (byte)(a & 0x80);
                a <<= 1;

                if (hiBitSet == 0x80)
                    a ^= 0x1b;

                b >>= 1;
            }

            return result;
        }

        // AddRoundKey - XOR состояния с ключом раунда
        private void AddRoundKey(byte[] state, byte[] roundKey)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] ^= roundKey[i];
            }
        }

        // Генерация расписания ключей
        private byte[][] KeyExpansion(byte[] key, int rounds)
        {
            int keySize = key.Length;
            int expandedSize = 16 * (rounds + 1);
            byte[][] roundKeys = new byte[rounds + 1][];

            // Первые N байт - исходный ключ
            byte[] expandedKey = new byte[expandedSize];
            Array.Copy(key, expandedKey, keySize);

            // Генерируем остальные ключи
            for (int i = keySize / 4; i < 4 * (rounds + 1); i++)
            {
                byte[] temp = new byte[4];
                Array.Copy(expandedKey, (i - 1) * 4, temp, 0, 4);

                if (i % (keySize / 4) == 0)
                {
                    // RotWord + SubWord + Rcon
                    RotWord(temp);
                    SubWord(temp);
                    temp[0] ^= Rcon[i / (keySize / 4)];
                }
                else if (keySize > 24 && i % (keySize / 4) == 4)
                {
                    SubWord(temp);
                }

                // XOR с предыдущим словом
                for (int j = 0; j < 4; j++)
                {
                    expandedKey[i * 4 + j] = (byte)(expandedKey[(i - keySize / 4) * 4 + j] ^ temp[j]);
                }
            }

            // Разделяем на ключи раундов
            for (int i = 0; i <= rounds; i++)
            {
                roundKeys[i] = new byte[16];
                Array.Copy(expandedKey, i * 16, roundKeys[i], 0, 16);
            }

            return roundKeys;
        }

        // Вспомогательные методы для KeyExpansion
        private void RotWord(byte[] word)
        {
            byte temp = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = temp;
        }

        private void SubWord(byte[] word)
        {
            // Используем прямой S-box для расширения ключа
            byte[] sBox = new byte[]
            {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            };

            for (int i = 0; i < 4; i++)
            {
                word[i] = sBox[word[i]];
            }
        }

        // Удаление padding PKCS7
        private byte[] RemovePadding(byte[] data)
        {
            if (data.Length == 0)
                return data;

            byte paddingValue = data[data.Length - 1];

            if (paddingValue == 0 || paddingValue > 16)
                return data; // Некорректный padding, возвращаем как есть

            // Проверяем padding
            for (int i = data.Length - paddingValue; i < data.Length; i++)
            {
                if (data[i] != paddingValue)
                    return data; // Некорректный padding, возвращаем как есть
            }

            // Удаляем padding
            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);

            return result;
        }

        // Удобный метод для дешифрования с HEX параметрами
        public string DecryptFromHex(string ciphertextHex, string keyHex, string ivHex, int keySize = 128)
        {
            try
            {
                byte[] ciphertext = HexStringToByteArray(ciphertextHex);
                byte[] key = HexStringToByteArray(keyHex);
                byte[] iv = HexStringToByteArray(ivHex);

                byte[] decrypted = DecryptManual(ciphertext, key, iv, keySize);
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                throw new CryptographicException($"Ошибка при дешифровании: {ex.Message}", ex);
            }
        }

        // Удобный метод для дешифрования с Base64
        public string DecryptFromBase64(string ciphertextBase64, string keyHex, string ivHex, int keySize = 128)
        {
            try
            {
                byte[] ciphertext = Convert.FromBase64String(ciphertextBase64);
                byte[] key = HexStringToByteArray(keyHex);
                byte[] iv = HexStringToByteArray(ivHex);

                byte[] decrypted = DecryptManual(ciphertext, key, iv, keySize);
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                throw new CryptographicException($"Ошибка при дешифровании: {ex.Message}", ex);
            }
        }

        // Вспомогательный метод для преобразования HEX строки в байты
        private byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "").ToUpper();

            if (hex.Length % 2 != 0)
                throw new FormatException("HEX строка должна иметь четное количество символов");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return bytes;
        }

        // Метод для проверки корректности дешифрования
        public bool VerifyDecryption(string originalText, byte[] ciphertext, byte[] key, byte[] iv, int keySize = 128)
        {
            try
            {
                byte[] decrypted = DecryptManual(ciphertext, key, iv, keySize);
                string decryptedText = Encoding.UTF8.GetString(decrypted);
                return decryptedText == originalText;
            }
            catch
            {
                return false;
            }
        }

        // Метод для пошагового дешифрования (для отладки)
        public List<string> StepByStepDecryption(byte[] ciphertext, byte[] key, byte[] iv, int keySize = 128)
        {
            List<string> steps = new List<string>();


            // Определяем количество раундов
            int rounds = keySize switch
            {
                128 => 10,
                192 => 12,
                256 => 14,
                _ => 10
            };

           

            // Генерируем расписание ключей
            byte[][] roundKeys = KeyExpansion(key, rounds);


            // Дешифруем первый блок
            if (ciphertext.Length >= 16)
            {
                byte[] firstBlock = new byte[16];
                Array.Copy(ciphertext, firstBlock, 16);

                

                byte[] state = new byte[16];
                Array.Copy(firstBlock, state, 16);

                // Начальный раунд
                
                AddRoundKey(state, roundKeys[rounds]);
               

                // Основные раунды
                for (int round = rounds - 1; round > 0; round--)
                {
                   

                   
                    InvShiftRows(state);
                   
                  
                    InvSubBytes(state);
                   
                   
                    AddRoundKey(state, roundKeys[round]);
                    

                    
                    InvMixColumns(state);
                  
                }

               
                InvShiftRows(state);
                
                InvSubBytes(state);
               
                AddRoundKey(state, roundKeys[0]);
               
            }

            return steps;
        }
    }
}
