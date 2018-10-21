using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPalsChallenge
{
    /// <seealso cref="https://cryptopals.com/sets/3/challenges/17"/>
    public static class Challenge17
    {
        private const int BLOCK_SIZE = 16;

        private static byte[] _keyBytes = Utility.CreateRandomKey();

        private static void Func1(out byte[] cipherText, out byte[] iv)
        {
            string[] textArray = Utility.GetResource("17.txt")
                .Split('\r', '\n')
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToArray();
            string s = textArray[Utility.Random() % textArray.Length];

            byte[] plainText = Encoding.ASCII.GetBytes(s);
            byte[] paddedPlainText = Challenge9.Pkcs7(plainText, BLOCK_SIZE);

            iv = Utility.CreateRandomKey();
            cipherText = Utility.Encrypt(paddedPlainText, _keyBytes, iv, CipherMode.CBC);           
        }

        private static bool Func2(byte[] cipherText, byte[] iv)
        {
            byte[] plainText = Utility.Decrypt(cipherText, _keyBytes, iv, CipherMode.CBC);
            return Challenge15.IsValidPkcs7Padding(plainText);
        }

        private static void DoOne()
        {
            // Create ciphertext and an IV
            Func1(out byte[] cipherText, out byte[] iv);

            // Prepare a buffer for the decoded plain text
            byte[] decodedPlainText = new byte[cipherText.Length];

            for (int i = 0; i < cipherText.Length; i += BLOCK_SIZE)
            {
                byte[] bytes = Utility.Concat(
                    new byte[BLOCK_SIZE],
                    Utility.Pluck(cipherText, i, BLOCK_SIZE));

                for (int j = BLOCK_SIZE - 1; j >= 0; j--)
                {
                    var candidates = new List<byte>();
                    for (int k = 0x00; k <= 0xFF; k++)
                    {
                        bytes[j] = (byte)k;
                        for (int x = j + 1; x < BLOCK_SIZE; x++)
                        {
                            bytes[x] = (byte)(
                                decodedPlainText[i + x] ^
                                (BLOCK_SIZE - j) ^
                                (i == 0 ? iv[x] : cipherText[i - BLOCK_SIZE + x]));
                        }

                        if (Func2(bytes, iv))
                        {
                            candidates.Add((byte)k);
                        }
                    }
                    if (candidates.Count != 1)
                    {
                        throw new Exception("Expected single candidate");
                    }

                    decodedPlainText[i + j] = (byte)(
                        (BLOCK_SIZE - j) ^
                        (i == 0 ? iv[j] : cipherText[i - BLOCK_SIZE + j]) ^
                        candidates[0]);
                }
            }

            byte[] strippedPlainText = Challenge15.StripPkcs7Padding(decodedPlainText);

            // Finally present the output
            string base64String = Encoding.ASCII.GetString(strippedPlainText);
            byte[] base64Bytes = Convert.FromBase64String(base64String);
            string finalString = Encoding.ASCII.GetString(base64Bytes);
            Console.WriteLine(finalString);
        }

        public static void Run()
        {
            for (int i = 0; i < 10; i++)
            {
                DoOne();
            }
        }
    }
}
