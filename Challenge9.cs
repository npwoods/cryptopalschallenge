using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoPalsChallenge
{
    public static class Challenge9
    {
        public static byte[] Pkcs7(byte[] bytes, int blockSize)
        {
            byte[] padding = new byte[blockSize - (bytes.Length % blockSize)];
            for (int i = 0; i < padding.Length; i++)
            {
                padding[i] = (byte)padding.Length;
            }
            return Utility.Concat(bytes, padding);
        }
    }
}
