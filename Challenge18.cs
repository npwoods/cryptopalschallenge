using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace CryptoPalsChallenge
{
    public static class Challenge18
    {
        public static void Run()
        {
            const int blockSize = 16;

            string s = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
            byte[] cipherText = Convert.FromBase64String(s);

            long nonce = 0;
            byte[] iv = new byte[blockSize];
            byte[] result = new byte[cipherText.Length];

            for (int i = 0; i < cipherText.Length; i += blockSize)
            {
                byte[] counter = Utility.Concat(
                    BitConverter.GetBytes(nonce),
                    BitConverter.GetBytes(i / blockSize));

                string key = "YELLOW SUBMARINE";
                byte[] encryptedCounter = Utility.Encrypt(
                    counter,
                    Encoding.ASCII.GetBytes(key),
                    iv,
                    CipherMode.CBC);

                for (int j = 0; j < blockSize && i + j < cipherText.Length; j++)
                {
                    result[i + j] = (byte)(cipherText[i + j] ^ encryptedCounter[j]);
                }
            }

            Console.WriteLine(Encoding.ASCII.GetString(result));
        }
    }
}
