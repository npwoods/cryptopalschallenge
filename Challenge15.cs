using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoPalsChallenge
{
    public static class Challenge15
    {
        private static int? GetPaddingCount(byte[] plainText)
        {
            byte padding = plainText[plainText.Length - 1];
            if (padding == 0)
            {
                return null;
            }
            for (int i = 1; i < padding; i++)
            {
                if (plainText[plainText.Length - 1 - i] != padding)
                {
                    return null;
                }
            }
            return padding;
        }

        public static bool IsValidPkcs7Padding(byte[] plainText)
        {
            return GetPaddingCount(plainText) != null;
        }

        public static byte[] StripPkcs7Padding(byte[] plainText)
        {
            int? paddingCount = GetPaddingCount(plainText);
            if (paddingCount == null)
            {
                throw new Exception("Bad padding");
            }
            return Utility.Pluck(plainText, 0, plainText.Length - paddingCount.Value);
        }
    }
}
