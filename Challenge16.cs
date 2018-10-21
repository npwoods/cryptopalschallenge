using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPalsChallenge
{
    /// <seealso cref="https://cryptopals.com/sets/2/challenges/16"/>
    public static class Challenge16
    {
        private const string PREFIX_STRING = "comment1=cooking%20MCs;userdata=";
        private const string SUFFIX_STRING = ";comment2=%20like%20a%20pound%20of%20bacon";

        private static readonly byte[] _keyBytes = Utility.CreateRandomKey();
        private static readonly byte[] _iv = new byte[16];

        static T[] Repeat<T>(T value, int count)
        {
            var result = new T[count];
            for (int i = 0; i < count; i++)
            {
                result[i] = value;
            }
            return result;
        }

        static IEnumerable<byte> Escape(byte[] bytes)
        {
            foreach(var b in bytes)
            {
                if (b == ';' || b == '=' || b == '%')
                {
                    string s = string.Format("%{0:X2}", (int)b);
                    foreach(var b2 in Encoding.ASCII.GetBytes(s))
                    {
                        yield return b2;
                    }
                }
                else
                {
                    yield return b;
                }
            }
        }

        static byte[] Func1(byte[] s)
        {
            byte[] quotedS = Escape(s).ToArray();

            byte[] concatenated = Utility.Concat(
                Encoding.ASCII.GetBytes(PREFIX_STRING),
                quotedS,
                Encoding.ASCII.GetBytes(SUFFIX_STRING));

            byte[] padded = Challenge9.Pkcs7(concatenated, 16);

            return Utility.Encrypt(padded, _keyBytes, _iv, CipherMode.CBC);
        }

        static bool Func2(byte[] cipherText)
        {
            byte[] plainText = Utility.Decrypt(cipherText, _keyBytes, _iv, CipherMode.CBC);
            byte[] unpaddedPlainText = Challenge15.StripPkcs7Padding(plainText);
            string s = Encoding.ASCII.GetString(unpaddedPlainText);
            string[] words = s.Split(';');
            return words.Contains("admin=true");
        }

        public static void Run()
        {
            const int blockSize = 16;
            int prefixLength = Encoding.ASCII.GetBytes(PREFIX_STRING).Length;
            int prefixBlocks = prefixLength / blockSize;
            int paddingLength = prefixLength - prefixBlocks * blockSize;

            byte[] s1 = Encoding.ASCII.GetBytes(";admin=true;");
            byte[] s2 = Escape(s1).ToArray();

            // Create the cipher text that we're trying to manipulate
            byte[] plainText = Utility.Concat(
                Repeat((byte) '_', paddingLength),
                s1);
            byte[] cipherText = Func1(plainText);

            // Tweak the ciphertext
            for (int i = 0; i < s1.Length; i++)
            {
                cipherText[prefixLength + paddingLength - blockSize + i] ^= (byte) (s1[i] ^ s2[i]);
            }

            // Attempt it!
            bool success = Func2(cipherText);
            Console.WriteLine($"success={success}");
        }

    }
}
