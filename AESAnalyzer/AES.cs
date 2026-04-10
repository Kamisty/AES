using System;
using System.Text;

namespace AESAnalyzer
{
    public class ManualAES
    {
        // S-бокс (SubBytes таблица)
        private static readonly byte[] SBox = new byte[256] {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        // Rcon (константы раундов)
        private static readonly byte[] Rcon = new byte[11] {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
        };

        // ========== ОСНОВНОЙ МЕТОД ШИФРОВАНИЯ ТЕКСТА ==========
        public byte[] EncryptTextManual(string text, string hexKey, byte[] iv, int selectedKeySize)
        {
            // 1. Преобразуем HEX ключ в байты
            byte[] key = HexStringToByteArray(hexKey);

            // 2. Проверяем соответствие размера ключа
            int expectedKeyLength = selectedKeySize / 8;
            if (key.Length != expectedKeyLength)
            {
                throw new ArgumentException(
                    $"Размер ключа не соответствует выбранному алгоритму AES-{selectedKeySize}.\n" +
                    $"Требуется: {expectedKeyLength} байт\n" +
                    $"Получено: {key.Length} байт\n" +
                    $"HEX ключ: {hexKey}");
            }

            // 3. Преобразуем текст в байты с дополнением PKCS7
            byte[] plainBytes = Encoding.UTF8.GetBytes(text);
            int padding = 16 - (plainBytes.Length % 16);
            if (padding == 0) padding = 16; // Если длина кратна 16, добавляем целый блок

            byte[] paddedBytes = new byte[plainBytes.Length + padding];
            Array.Copy(plainBytes, paddedBytes, plainBytes.Length);

            // Заполняем байтами padding
            for (int i = plainBytes.Length; i < paddedBytes.Length; i++)
            {
                paddedBytes[i] = (byte)padding;
            }

            // 4. Шифруем каждый блок в режиме CBC
            byte[] result = new byte[paddedBytes.Length];
            byte[] currentIV = new byte[16];
            Array.Copy(iv, currentIV, 16);

            for (int i = 0; i < paddedBytes.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(paddedBytes, i, block, 0, 16);

                // CBC режим: XOR с IV или предыдущим зашифрованным блоком
                for (int j = 0; j < 16; j++)
                {
                    block[j] ^= currentIV[j];
                }

                // Шифруем блок
                byte[] encryptedBlock = EncryptAES_Manual(block, key, selectedKeySize);

                // Копируем результат
                Array.Copy(encryptedBlock, 0, result, i, 16);

                // Обновляем IV для следующего блока (CBC режим)
                Array.Copy(encryptedBlock, currentIV, 16);
            }

            return result;
        }

        // ========== ШИФРОВАНИЕ ОДНОГО БЛОКА AES ==========
        public byte[] EncryptAES_Manual(byte[] input, byte[] key, int selectedKeySize)
        {
            // Проверка размера ключа
            int expectedKeyLength = selectedKeySize / 8;
            if (key.Length != expectedKeyLength)
            {
                throw new ArgumentException(
                    $"Неправильный размер ключа для AES-{selectedKeySize}. " +
                    $"Ожидается {expectedKeyLength} байт, получено {key.Length} байт.");
            }

            // Проверка размера входного блока
            if (input.Length != 16)
            {
                throw new ArgumentException(
                    $"Входной блок должен быть 16 байт, получено {input.Length} байт.");
            }

            // Определяем количество раундов
            int Nr = selectedKeySize switch
            {
                128 => 10,
                192 => 12,
                256 => 14,
                _ => throw new ArgumentException("Неподдерживаемый размер ключа: " + selectedKeySize)
            };

            int Nk = selectedKeySize / 32; // 4, 6 или 8 слов

            // 1. Генерация раундовых ключей (Key Expansion)
            byte[,] roundKeys = KeyExpansion(key, Nk, Nr);

            // 2. Копируем входной блок
            byte[] state = new byte[16];
            Array.Copy(input, state, 16);

            // 3. Начальный AddRoundKey
            AddRoundKey(state, roundKeys, 0);

            // 4. Основные раунды
            for (int round = 1; round < Nr; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, roundKeys, round);
            }

            // 5. Финальный раунд (без MixColumns)
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, roundKeys, Nr);

            return state;
        }

        // ========== 1. KEY EXPANSION ==========
        private byte[,] KeyExpansion(byte[] key, int Nk, int Nr)
        {
            int Nb = 4;
            byte[,] w = new byte[4, 4 * (Nr + 1)];

            // Копируем исходный ключ
            for (int i = 0; i < Nk; i++)
            {
                w[0, i] = key[4 * i];
                w[1, i] = key[4 * i + 1];
                w[2, i] = key[4 * i + 2];
                w[3, i] = key[4 * i + 3];
            }

            // Расширяем ключ
            for (int i = Nk; i < Nb * (Nr + 1); i++)
            {
                byte[] temp = new byte[4];
                temp[0] = w[0, i - 1];
                temp[1] = w[1, i - 1];
                temp[2] = w[2, i - 1];
                temp[3] = w[3, i - 1];

                if (i % Nk == 0)
                {
                    // RotWord + SubWord + Rcon
                    RotWord(temp);
                    SubWord(temp);
                    temp[0] ^= Rcon[i / Nk];
                }
                else if (Nk > 6 && i % Nk == 4)
                {
                    SubWord(temp);
                }

                w[0, i] = (byte)(w[0, i - Nk] ^ temp[0]);
                w[1, i] = (byte)(w[1, i - Nk] ^ temp[1]);
                w[2, i] = (byte)(w[2, i - Nk] ^ temp[2]);
                w[3, i] = (byte)(w[3, i - Nk] ^ temp[3]);
            }

            return w;
        }

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
            for (int i = 0; i < 4; i++)
            {
                word[i] = SBox[word[i]];
            }
        }

        // ========== 2. SUBBYTES ==========
        private void SubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] = SBox[state[i]];
            }
        }

        // ========== 3. SHIFTROWS ==========
        private void ShiftRows(byte[] state)
        {
            // Row 0 - не сдвигается
            // Row 1 - сдвиг на 1
            byte temp = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = temp;

            // Row 2 - сдвиг на 2
            temp = state[2];
            state[2] = state[10];
            state[10] = temp;
            temp = state[6];
            state[6] = state[14];
            state[14] = temp;

            // Row 3 - сдвиг на 3
            temp = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7] = state[3];
            state[3] = temp;
        }

        // ========== 4. MIXCOLUMNS ==========
        private void MixColumns(byte[] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte s0 = state[i * 4];
                byte s1 = state[i * 4 + 1];
                byte s2 = state[i * 4 + 2];
                byte s3 = state[i * 4 + 3];

                state[i * 4] = (byte)(GMul(s0, 2) ^ GMul(s1, 3) ^ s2 ^ s3);
                state[i * 4 + 1] = (byte)(s0 ^ GMul(s1, 2) ^ GMul(s2, 3) ^ s3);
                state[i * 4 + 2] = (byte)(s0 ^ s1 ^ GMul(s2, 2) ^ GMul(s3, 3));
                state[i * 4 + 3] = (byte)(GMul(s0, 3) ^ s1 ^ s2 ^ GMul(s3, 2));
            }
        }

        // Умножение в поле GF(2^8)
        private byte GMul(byte a, byte b)
        {
            byte p = 0;
            byte hi_bit_set;

            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                {
                    a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
                }

                b >>= 1;
            }

            return p;
        }

        // ========== 5. ADDROUNDKEY ==========
        private void AddRoundKey(byte[] state, byte[,] roundKeys, int round)
        {
            for (int i = 0; i < 16; i++)
            {
                int row = i % 4;
                int col = round * 4 + i / 4;
                state[i] ^= roundKeys[row, col];
            }
        }

        // ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========

        // Метод для преобразования HEX строки в байты
        private byte[] HexStringToByteArray(string hex)
        {
            if (string.IsNullOrEmpty(hex))
                throw new ArgumentException("HEX строка не может быть пустой");

            hex = hex.Replace("-", "").Replace(" ", "").ToUpper();

            if (hex.Length % 2 != 0)
            {
                throw new FormatException("HEX строка должна иметь четное количество символов");
            }

            byte[] bytes = new byte[hex.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                try
                {
                    bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                }
                catch (FormatException)
                {
                    throw new FormatException($"Некорректный HEX символ в позиции {i * 2}: '{hex.Substring(i * 2, 2)}'");
                }
            }

            return bytes;
        }

        // Метод для дешифрования (опционально, если нужно)
        public byte[] DecryptTextManual(byte[] ciphertext, string hexKey, byte[] iv, int selectedKeySize)
        {
            // Для дешифрования нужна Inverse S-Box и другие операции
            // Пока оставляем заглушку
            throw new NotImplementedException("Дешифрование пока не реализовано");
        }

        // Простой метод для одного блока (без CBC, ECB режим)
        public byte[] EncryptSingleBlock(byte[] block, string hexKey, int selectedKeySize)
        {
            byte[] key = HexStringToByteArray(hexKey);
            byte[] iv = new byte[16]; // нулевой IV для ECB режима

            // ECB: просто шифруем блок без XOR с IV
            return EncryptAES_Manual(block, key, selectedKeySize);
        }

        // Метод для отображения состояния в читаемом формате
        public string StateToString(byte[] state)
        {
            if (state.Length != 16)
                return "Неверный размер состояния";

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    sb.AppendFormat("{0:X2} ", state[i * 4 + j]);
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }

        // Метод для проверки корректности S-Box
        public bool ValidateSBox()
        {
            // Простая проверка: SBox должен содержать все значения 0x00-0xFF
            bool[] found = new bool[256];

            foreach (byte b in SBox)
            {
                found[b] = true;
            }

            for (int i = 0; i < 256; i++)
            {
                if (!found[i])
                    return false;
            }

            return true;
        }
    }
}