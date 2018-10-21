using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPalsChallenge
{
    class Program
    {

        static byte[] FromHex(string str)
        {
            byte[] bytes = new byte[str.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = byte.Parse(str.Substring(i * 2, 2), NumberStyles.HexNumber);
            }
            return bytes;
        }

        static string ToHex(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.AppendFormat("{0:x2}", bytes[i]);
            }
            return builder.ToString();
        }

        static byte[] XorBytes(byte[] b1, byte[] b2)
        {
            return Challenge2.XorBytes(b1, b2);
        }

        static byte[] XorBytes(byte[] b1, byte b2)
        {
            var result = new byte[b1.Length];
            for (int i = 0; i < b1.Length; i++)
            {
                result[i] = (byte)(b1[i] ^ b2);
            }
            return result;
        }

        static int HammingDistance(Span<byte> b1, Span<byte> b2)
        {
            int result = 0;
            for (int i = 0; i < b1.Length; i++)
            {
                byte b = (byte)(b1[i] ^ b2[i]);
                while (b > 0)
                {
                    if ((b & 0x01) == 0x01)
                        result++;
                    b >>= 1;
                }
            }
            return result;
        }

        static bool LooksLikeAscii(byte b)
        {
            return (b >= 32 && b <= 127)
                || (b == 13) || (b == 10);
        }

        static string SingleCharacterXor(IEnumerable<byte> cipherText, byte xor)
        {
            var decodedBytes = cipherText.Select(b => (byte)(b ^ xor)).ToArray();
            return decodedBytes.All(LooksLikeAscii)
                ? Encoding.ASCII.GetString(decodedBytes).Replace('\r', '\n')
                : null;
        }

        private static IEnumerable<T> Stagger<T>(Span<T> buffer, int chunkSize, int position)
        {
            var result = new List<T>();
            for (int i = position; i < buffer.Length; i += chunkSize)
            {
                result.Add(buffer[i]);
            }
            return result;
        }

        private static IEnumerable<T> Stagger<T>(T[] buffer, int chunkSize, int position)
        {
            Span<T> span = buffer;
            return Stagger(span, chunkSize, position);
        }

        static void Challenge4()
        {
            string[] textArray = Utility.GetResource("4.txt").Split('\r', '\n');
            for (int i = 0; i < textArray.Length; i++)
            {
                var cipherText = FromHex(textArray[i]);
                var bytes = new byte[cipherText.Length];

                for (int xor = 0x00; xor <= 0xFF; xor++)
                {
                    string s = SingleCharacterXor(cipherText, (byte)xor);
                    if (s != null)
                    {
                        Console.WriteLine($"{i}:{xor}: {s}");
                    }
                }
            }
        }

        /// <summary>
        /// Gauge which key sizes are likely to be the target
        /// </summary>
        static int[] AppraiseKeySizes(Span<byte> cipherText)
        {
            var dict = new Dictionary<int, double>();
            for (int keySize = 2; keySize <= 40; keySize++)
            {
                double distance = 0;
                Span<byte> firstSlice = cipherText.Slice(0, keySize);
                for (int i = 1; i <= 10; i++)
                {
                    Span<byte> thisSlice = cipherText.Slice(keySize * i, keySize);
                    distance += HammingDistance(firstSlice, thisSlice) / (double)keySize;
                }

                dict.Add(keySize, distance);
            }

            return (from keySize in dict.Keys.OrderBy(ks => dict[ks])
                    select keySize).ToArray();
        }

        private struct PossibleXor
        {
            public byte Xor;
            public int Quality;
        }

        static IEnumerable<byte[]> EnumeratePossibleKeys(byte[] cipherText, int keySize)
        {
            var possibleXors = new List<PossibleXor>[keySize];

            for (int i = 0; i < keySize; i++)
            {
                possibleXors[i] = new List<PossibleXor>();
                for (int xor = 0x00; xor <= 0xFF; xor++)
                {
                    var stag = Stagger<byte>(cipherText, keySize, i);
                    string s = SingleCharacterXor(stag, (byte)xor);
                    if (s != null)
                    {
                        PossibleXor px;
                        px.Xor = (byte)xor;
                        px.Quality = s.Count(c => char.IsLetter(c) || c == ' ');
                        possibleXors[i].Add(px);
                    }
                }

                // Sort by our quality heuristic - we don't know precisely which printable characters will be
                // present and which ones won't be, but we know that letters are likely
                possibleXors[i].Sort((x, y) => System.Collections.Comparer.Default.Compare(y.Quality, x.Quality));
            }

            // We now have a list of possible XORs for each position.  Now we need to return
            // every permutation
            var indexes = new int[keySize];
            var result = new byte[keySize];
            bool done = false;
            while(!done)
            {
                // Build the result and return it
                for (int i = 0; i < keySize; i++)
                    result[i] = possibleXors[i][indexes[i]].Xor;
                yield return result;

                // Bump the counter
                bool doneIncrementing = false;
                int incrementPos = 0;
                while(!doneIncrementing && incrementPos < keySize)
                {
                    doneIncrementing = ++indexes[incrementPos] < possibleXors[incrementPos].Count;
                    if (!doneIncrementing)
                        indexes[incrementPos++] = 0;
                }

                done = incrementPos >= keySize;
            }
        }

        private static string TryDecode(byte[] cipherText, byte[] key)
        {
            byte[] decodedCipherText = new byte[cipherText.Length];
            for (int i = 0; i < decodedCipherText.Length; i++)
            {
                decodedCipherText[i] = (byte)(cipherText[i] ^ key[i % key.Length]);
            }
            return Encoding.ASCII.GetString(decodedCipherText);
        }

        static void Challenge6()
        {
            string text = Utility.GetResource("6.txt");
            byte[] cipherText = Convert.FromBase64String(text);

            // Get candidate keys
            var candidates = from keySize in AppraiseKeySizes(cipherText)
                             from possibleKey in EnumeratePossibleKeys(cipherText, keySize)
                             select TryDecode(cipherText, possibleKey);

            foreach(var cand in candidates)
            {
                Console.WriteLine(cand);
                Console.WriteLine("---------------");
            }
        }

        static byte[] EcbDecrypt(byte[] cipherText, byte[] keyBytes)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.Padding = PaddingMode.None;
                aes.Mode = CipherMode.ECB;

                using (var decryptor = aes.CreateDecryptor(keyBytes, aes.IV))
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (MemoryStream target = new MemoryStream())
                {
                    var buffer = new byte[1024];
                    int len;
                    while((len = csDecrypt.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        target.Write(buffer, 0, len);
                    }
                    return target.ToArray();
                }
            }
        }

        static byte[] Encrypt(byte[] plainText, byte[] keyBytes, byte[] iv, CipherMode cipherMode)
        {
            return Utility.Encrypt(plainText, keyBytes, iv, cipherMode);
        }

        static void Challenge7()
        {
            string text = Utility.GetResource("7.txt");
            byte[] cipherText = Convert.FromBase64String(text);

            string key = "YELLOW SUBMARINE";
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);

            byte[] resultBytes = EcbDecrypt(cipherText, keyBytes);
            Console.WriteLine(Encoding.ASCII.GetString(resultBytes));
        }

        static void Challenge8()
        {
            string[] texts = (from string line in Utility.GetResource("8.txt").Split('\r', '\n')
                              where !string.IsNullOrEmpty(line)
                              select line).ToArray();
            byte[][] cipherTexts = texts.Select(FromHex).ToArray();

            var distances = new Dictionary<int, int>();
            for (int i = 0; i < cipherTexts.Length; i++)
            {
                if (cipherTexts[i].Length != 160)
                {
                    throw new Exception();
                }
                int dist = 0;
                for (int j = 0; j < 16; j++)
                {
                    dist += Stagger(cipherTexts[i], 16, j).Distinct().Count();
                }
                distances[i] = dist;
            }

            foreach(var index in distances.OrderBy(pair => pair.Value).Select(pair => pair.Key))
            {
                Console.WriteLine($"index={index} distance={distances[index]}");
            }
        }

        static byte[] Pkcs7(byte[] bytes, int multiple)
        {
            int paddingSize = multiple - (bytes.Length % multiple);
            byte[] newBytes = new byte[bytes.Length + paddingSize];

            for (int i = 0; i < bytes.Length; i++)
            {
                newBytes[i] = bytes[i];
            }
            for (int i = bytes.Length; i < newBytes.Length; i++)
            {
                newBytes[i] = (byte)paddingSize;
            }
            return newBytes;
        }

        static void Challenge9()
        {
            byte[] bytes = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            byte[] newBytes = Pkcs7(bytes, 20);
        }

        private static byte[] CbcDecrypt(byte[] cipherText, byte[] keyBytes)
        {
            using (MemoryStream memStream = new MemoryStream())
            {
                const int chunkSize = 16;

                byte[] lastChunk = new byte[chunkSize];
                for (int i = 0; i < cipherText.Length; i += chunkSize)
                {
                    int thisChunkSize = Math.Min(chunkSize, cipherText.Length - i);
                    byte[] chunk = new byte[thisChunkSize];
                    Array.Copy(cipherText, i, chunk, 0, thisChunkSize);

                    byte[] decodedBytes = EcbDecrypt(chunk, keyBytes);
                    for (int j = 0; j < decodedBytes.Length; j++)
                    {
                        decodedBytes[j] ^= lastChunk[j];
                    }

                    lastChunk = chunk;

                    memStream.Write(decodedBytes, 0, decodedBytes.Length);
                }
                return memStream.ToArray();
            }
        }

        static void Challenge10()
        {
            byte[] keyBytes = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            string text = Utility.GetResource("10.txt");
            byte[] cipherText = Convert.FromBase64String(text);

            byte[] decodedBytes = CbcDecrypt(cipherText, keyBytes);
            Console.Write(Encoding.ASCII.GetString(decodedBytes));
        }

        static byte[] EncryptionOracle(byte[] plainText, out CipherMode mode)
        {
            var rand = new Random();

            // Generate random key
            byte[] keyBytes = new byte[16];
            rand.NextBytes(keyBytes);

            // Prepend and append random bytes
            int prependBytes = rand.Next() % 6 + 5;
            int appendBytes = rand.Next() % 6 + 5;
            byte[] newPlainText = new byte[plainText.Length + prependBytes + appendBytes];
            rand.NextBytes(newPlainText);
            Array.Copy(plainText, 0, newPlainText, prependBytes, plainText.Length);

            byte[] randomIv = new byte[16];
            rand.NextBytes(randomIv);

            mode = rand.Next() % 2 == 0 ? CipherMode.CBC : CipherMode.ECB;
            return Encrypt(
                newPlainText,
                keyBytes,
                mode == CipherMode.CBC ? randomIv : null,
                mode);
        }

        static void Challenge11()
        {
            // A big zero byte plaintext
            byte[] plainText = new byte[0x1000];

            for (int i = 0; i < 20; i++)
            {
                byte[] cipherText = EncryptionOracle(plainText, out CipherMode actualMode);

                int dist = 0;
                for (int j = 0; j < 16; j++)
                {
                    dist += Stagger(cipherText, 16, j).Distinct().Count();
                }

                var predictedCipherMode = dist > 200 ? CipherMode.CBC : CipherMode.ECB;


                Console.WriteLine($"predictedCipherMode={predictedCipherMode} actualMode={actualMode} success={predictedCipherMode == actualMode}");
            }
        }

        static byte[] RandomKey()
        {
            var rand = new Random();
            var bytes = new byte[16];
            rand.NextBytes(bytes);
            return bytes;
        }

        private static byte[] keyBytesChallenge12 = RandomKey();

        static byte[] EncryptionOracle12(byte[] plainText)
        {
            var keyBytes = keyBytesChallenge12;

            // Prepend and append random bytes
            byte[] appendBytes = Convert.FromBase64String(Utility.GetResource("12.txt"));
            byte[] newPlainText = Utility.Concat(plainText, appendBytes);

            return Encrypt(
                newPlainText,
                keyBytes,
                null,
                CipherMode.ECB);
        }

        static byte[] Repeat(byte b, int count)
        {
            var result = new byte[count];
            for (int i = 0; i < count; i++)
            {
                result[i] = b;
            }
            return result;
        }

        static bool Compare<T>(T[] array1, int startX, T[] array2, int startY, int count)
        {
            if (startX < 0) throw new ArgumentOutOfRangeException(nameof(startX));
            if (startY < 0) throw new ArgumentOutOfRangeException(nameof(startY));
            if ((count < 0) || (startX + count > array1.Length) || (startY + count > array2.Length))
                throw new ArgumentOutOfRangeException(nameof(count));

            for (int i = 0; i < count; i++)
            {
                if (!Equals(array1[startX + i], array2[startY + i]))
                    return false;
            }
            return true;
        }

        static bool Compare<T>(T[] array, int startX, int startY, int count)
        {
            return Compare(array, startX, array, startY, count);
        }

        static void Challenge12()
        {
            int GetKeySize()
            {
                int potentialKeySize;
                for (potentialKeySize = 1; potentialKeySize < 32; potentialKeySize++)
                {
                    byte[] bytes = Repeat(42, potentialKeySize * 2);
                    byte[] encryptedBytes = EncryptionOracle12(bytes);
                    if (Compare(encryptedBytes, 0, potentialKeySize, potentialKeySize))
                        return potentialKeySize;
                }
                throw new Exception();
            }

            // Get the key size
            int keySize = GetKeySize();

            // Is this ECB?
            byte[] zeroPlainText = new byte[0x1000];
            byte[] zeroCipherText = EncryptionOracle12(zeroPlainText);
            int dist = 0;
            for (int j = 0; j < keySize; j++)
            {
                dist += Stagger(zeroCipherText, keySize, j).Distinct().Count();
            }
            bool isECB = dist <= 200;
            if (!isECB)
                throw new Exception();

            // Get the length of the message we're trying to decode
            int messageLength = zeroCipherText.Length - zeroPlainText.Length;

            byte[] decodedMessage = new byte[messageLength];
            for (int i = 0; i < messageLength; i++)
            {
                byte arbitraryByte = 42;
                var buffer = Repeat(arbitraryByte, keySize - 1 - (i % keySize));
                byte[] encryptedBuffer = EncryptionOracle12(buffer);

                byte? thisByte = null;
                for (int b = 0x00; thisByte == null && (b <= 0xFF); b++)
                {
                    var concatBuffer = Utility.Concat(
                        buffer,
                        Utility.Pluck(decodedMessage, 0, i),
                        new[] { (byte)b });
                    var encryptedConcatBuffer = EncryptionOracle12(concatBuffer);
                    if (Compare(encryptedBuffer, 0, encryptedConcatBuffer, 0, concatBuffer.Length))
                        thisByte = (byte)b;
                }
                decodedMessage[i] = thisByte.Value;
            }

            Console.Write(Encoding.ASCII.GetString(decodedMessage).Replace("\0", ""));
        }

        static string ProfileFor(string email)
        {
            var queryBuilder = new QueryBuilder();
            queryBuilder.Add("email", email);
            queryBuilder.Add("uid", "10");
            queryBuilder.Add("role", "user");
            return queryBuilder.ToQueryString().Value;
        }

        static void Challenge13()
        {
            var keyBytes = RandomKey();

            string profile = ProfileFor("foo@bar.com");
            byte[] encryptedProfile = Encrypt(Encoding.ASCII.GetBytes(profile), keyBytes, null, CipherMode.ECB);


            byte[] decryptedProfile = EcbDecrypt(encryptedProfile, keyBytes);
            var parsed = QueryHelpers.ParseQuery(Encoding.ASCII.GetString(decryptedProfile));
        }

        static byte[] _encryptionOracle14Prefix;

        static byte[] EncryptionOracle14(byte[] plainText)
        {
            if (_encryptionOracle14Prefix == null)
            {
                var r = new Random();
                _encryptionOracle14Prefix = new byte[(r.Next() % 100) + 50];
                r.NextBytes(_encryptionOracle14Prefix);                
            }
            var concatPlainText = Utility.Concat(_encryptionOracle14Prefix, plainText);
            return EncryptionOracle12(concatPlainText);
        }

        static void Challenge14()
        {
            int GetKeySize()
            {
                byte[] encryptedEmptyBytes = EncryptionOracle14(new byte[0]);

                int potentialKeySize;
                for (potentialKeySize = 1; potentialKeySize < 32; potentialKeySize++)
                {
                    byte[] bytes = Repeat(42, potentialKeySize);
                    byte[] encryptedBytes = EncryptionOracle14(bytes);
                    if (Compare(encryptedEmptyBytes, encryptedEmptyBytes.Length - potentialKeySize, encryptedBytes, encryptedBytes.Length - potentialKeySize, potentialKeySize))
                        return potentialKeySize;
                }
                throw new Exception();
            }

            // Get the key size
            int keySize = GetKeySize();

            // Now determine how many complete prefix blocks we have
            var cipherText1 = EncryptionOracle14(Enumerable.Range(0, keySize).Select(i => (byte)i).ToArray());
            var cipherText2 = EncryptionOracle14(Enumerable.Range(1, keySize).Select(i => (byte)i).ToArray());
            int completePrefixBlocks = 0;
            while (Compare(cipherText1, completePrefixBlocks * keySize, cipherText2, completePrefixBlocks * keySize, keySize))
                completePrefixBlocks++;

            bool TryPartialPrefixSize(int potentialPartialPrefixLength)
            {
                // Arbitrary values, must be different
                const byte b1 = 0x00;
                const byte b2 = 0xFF;

                var buffer1 = Utility.Concat(
                    Repeat(b1, keySize - potentialPartialPrefixLength),
                    Repeat(b2, potentialPartialPrefixLength));
                var buffer2 = Repeat(b2, keySize);

                var encryptedBuffer1 = EncryptionOracle14(buffer1);
                var encryptedBuffer2 = EncryptionOracle14(buffer2);

                return Compare(
                    encryptedBuffer1, (completePrefixBlocks + 1) * keySize,
                    encryptedBuffer2, (completePrefixBlocks + 1) * keySize,
                    keySize);
            }

            // Now determine the partial prefix size
            int partialPrefixLength = keySize - 1;
            while (partialPrefixLength > 0 && TryPartialPrefixSize(partialPrefixLength - 1))
                partialPrefixLength--;

            // We now know the full prefix length
            int prefixLength = completePrefixBlocks * keySize + partialPrefixLength;

            // Get the length of the message we're trying to decode
            int messageLength = EncryptionOracle14(new byte[] { }).Length - prefixLength;

            // Create padding to neutralize the prefix
            var padding = Repeat(0xCD, keySize - partialPrefixLength);
            int paddedOffset = keySize * (completePrefixBlocks + 1);

            byte[] decodedMessage = new byte[messageLength];
            for (int i = 0; i < messageLength; i++)
            {
                byte arbitraryByte = 42;
                var buffer = Utility.Concat(
                    padding,
                    Repeat(arbitraryByte, keySize - 1 - (i % keySize)));
                byte[] encryptedBuffer = EncryptionOracle14(buffer);

                byte? thisByte = null;
                for (int b = 0x00; thisByte == null && (b <= 0xFF); b++)
                {
                    var concatBuffer = Utility.Concat(
                        buffer,
                        Utility.Pluck(decodedMessage, 0, i),
                        new[] { (byte)b });
                    var encryptedConcatBuffer = EncryptionOracle14(concatBuffer);
                    if (Compare(encryptedBuffer, paddedOffset, encryptedConcatBuffer, paddedOffset, concatBuffer.Length - padding.Length))
                        thisByte = (byte)b;
                }
                decodedMessage[i] = thisByte.Value;
            }

            Console.Write(Encoding.ASCII.GetString(decodedMessage).Replace("\0", ""));
        }

        static void Main(string[] args)
        {
            Challenge16.Run();
            Console.ReadLine();            
        }
    }
}
