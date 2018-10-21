using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoPalsChallenge
{
    public static class Challenge2
    {
        public static byte[] XorBytes(byte[] b1, byte[] b2)
        {
            var result = new byte[b1.Length];
            for (int i = 0; i < b1.Length; i++)
            {
                result[i] = (byte)(b1[i] ^ b2[i % b2.Length]);
            }
            return result;
        }
    }
}
