using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPalsChallenge
{
    public static class Utility
    {
        private static Random _random = new Random();
        private static Lazy<HashSet<string>> _dictionary = new Lazy<HashSet<string>>(BuildDictionary);

        /// <summary>
        /// Reads a resource
        /// </summary>
        public static string GetResource(string name)
        {
            var assembly = Assembly.GetEntryAssembly();
            var resourceStream = assembly.GetManifestResourceStream($"CryptoPalsChallenge.Resources.{name}");
            using (var reader = new StreamReader(resourceStream, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        public static int Random()
        {
            return _random.Next();
        }
        public static int Random(int x)
        {
            return Random() % x;
        }

        public static byte[] CreateRandomKey()
        {
            // Generate random key
            byte[] keyBytes = new byte[16];
            _random.NextBytes(keyBytes);
            return keyBytes;
        }

        public static T[] Concat<T>(IEnumerable<T[]> arrays)
        {
            int totalLength = arrays.Sum(a => a.Length);
            var result = new T[totalLength];

            int pos = 0;
            foreach (var arr in arrays)
            {
                Array.Copy(arr, 0, result, pos, arr.Length);
                pos += arr.Length;
            }
            return result;
        }

        public static T[] Concat<T>(params T[][] arrays)
        {
            IEnumerable<T[]> enumerable = arrays;
            return Concat(enumerable);
        }

        public static T[] Dupe<T>(T[] array)
        {
            return Concat(array);
        }

        public static T[] Pluck<T>(T[] array, int position, int length)
        {
            var result = new T[length];
            Array.Copy(array, position, result, 0, length);
            return result;
        }

        public static IEnumerable<T> Stagger<T>(Span<T> buffer, int chunkSize, int position)
        {
            var result = new List<T>();
            for (int i = position; i < buffer.Length; i += chunkSize)
            {
                result.Add(buffer[i]);
            }
            return result;
        }

        public static IEnumerable<T> Stagger<T>(T[] buffer, int chunkSize, int position)
        {
            Span<T> span = buffer;
            return Stagger(span, chunkSize, position);
        }

        public static byte[] Encrypt(byte[] plainText, byte[] keyBytes, byte[] iv, CipherMode cipherMode)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                if (iv != null)
                {
                    aes.IV = iv;
                }
                aes.Padding = PaddingMode.Zeros;
                aes.Mode = cipherMode;

                using (var encryptor = aes.CreateEncryptor(keyBytes, aes.IV))
                using (MemoryStream msEncrypt = new MemoryStream(plainText))
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Read))
                using (MemoryStream target = new MemoryStream())
                {
                    var buffer = new byte[1024];
                    int len;
                    while ((len = csEncrypt.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        target.Write(buffer, 0, len);
                    }
                    return target.ToArray();
                }
            }
        }

        public static byte[] Decrypt(byte[] cipherText, byte[] keyBytes, byte[] iv, CipherMode cipherMode)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.Padding = PaddingMode.None;
                aes.Mode = cipherMode;
                if (iv != null)
                {
                    aes.IV = iv;
                }

                using (var decryptor = aes.CreateDecryptor(keyBytes, aes.IV))
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (MemoryStream target = new MemoryStream())
                {
                    var buffer = new byte[1024];
                    int len;
                    while ((len = csDecrypt.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        target.Write(buffer, 0, len);
                    }
                    return target.ToArray();
                }
            }
        }

        private static HashSet<string> BuildDictionary()
        {
            // Not sure what is up with this dictionary, but it requires tweaks
            var augmentations = new string[]
            {
                "/",
                "are",
                "came",
                "cuz"
            };
            var substitutions = new Dictionary<string, string>
            {
                {"i", "I"},
                {"TO", "to"},
                {"BUT", "but"}
            };

            IEnumerable<string> words = from word in GetResource("Dictionary.txt").Split('\r', '\n').Concat(augmentations)
                                        let substWord = substitutions.ContainsKey(word) ? substitutions[word] : word
                                        where !string.IsNullOrWhiteSpace(substWord)
                                        select substWord;
            return new HashSet<string>(words);
        }

        public static bool IsWord(string word)
        {
            bool success = InternalIsWord(word) || InternalIsWord(word.ToLowerInvariant());

            // We love 90's rap - calibrate accordingly
            if (!success && word.EndsWith("n'"))
            {
                string newWord = word.Substring(0, word.Length - 2) + "ng";
                success = InternalIsWord(newWord) || InternalIsWord(newWord.ToLowerInvariant());
            }
            return success;
        }

        private static bool InternalIsWord(string word)
        {
            return _dictionary.Value.Contains(word);
        }
    }
}
