using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace CryptoPalsChallenge
{
    public static class Challenge18
    {
        public static byte[] CtrEncodeDecode(byte[] input, byte[] keyBytes, long nonce = 0)
        {
            const int blockSize = 16;

            byte[] iv = new byte[blockSize];
            byte[] result = new byte[input.Length];

            for (int i = 0; i < input.Length; i += blockSize)
            {
                byte[] counter = Utility.Concat(
                    BitConverter.GetBytes(nonce),
                    BitConverter.GetBytes(i / blockSize));

                byte[] encryptedCounter = Utility.Encrypt(
                    counter,
                    keyBytes,
                    iv,
                    CipherMode.CBC);

                for (int j = 0; j < blockSize && i + j < input.Length; j++)
                {
                    result[i + j] = (byte)(input[i + j] ^ encryptedCounter[j]);
                }
            }
            return result;
        }

        public static void Run()
        {
            string s = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
            byte[] cipherText = Convert.FromBase64String(s);
            byte[] keyBytes = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");

            byte[] result = CtrEncodeDecode(cipherText, keyBytes);

            Console.WriteLine(Encoding.ASCII.GetString(result));
        }
    }
}
