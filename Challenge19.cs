using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CryptoPalsChallenge
{
    /// <seealso cref="https://cryptopals.com/sets/3/challenges/19"/>
    public static class Challenge19
    {
        // A fixed random key
        private static readonly byte[] _keyBytes = new byte[] { 0xAA, 0xA1, 0x25, 0x03, 0xAF, 0xCD, 0x73, 0xE6, 0x6E, 0x49, 0x7A, 0x0F, 0xE1, 0x8D, 0x3E, 0x97 };

        public static void DumpMasks(byte[][] xoredCipherText, byte mask)
        {
            int count = xoredCipherText.Max(a => a.Length);

            for (int i = 0; i < count; i++)
            {
                var dict = new Dictionary<int, int>();
                var samples = xoredCipherText
                    .Where(a => a.Length > i)
                    .Select(a => a[i])
                    .ToArray();

                foreach (var b in samples)
                {
                    var key = b & mask;
                    if (!dict.ContainsKey(key))
                    {
                        dict.Add(key, 0);
                    }
                    dict[key]++;
                }
                foreach (var key in dict.Keys.OrderBy(x => x))
                {
                    Console.WriteLine($"key[{i}]: CountOf[0x{key:X2}] = {dict[key]}");
                }
            }
        }

        private static int Score(byte b)
        {
            char ch = (char)b;
            int result;

            if (b >= 0x80)
                result = 0;
            else if (" '\"0123456789".Contains(ch))
                result = 1100;
            else if (char.IsPunctuation(ch) || char.IsWhiteSpace(ch) || char.IsNumber(ch))
                result = 1000;
            else if (char.IsUpper(ch))
                result = 1300;
            else if (char.IsLower(ch))
                result = 1500;
            else
                result = 0;

            if (char.IsLetter(ch))
            {
                if ("RSTLNE".IndexOf(ch, StringComparison.InvariantCultureIgnoreCase) >= 0)
                    result += 50;
                else if ("CDMA".IndexOf(ch, StringComparison.InvariantCultureIgnoreCase) >= 0)
                    result += 30;
            }

            return result;
        }

        public static byte[][] CtrEncodeBase64Strings(string text)
        {
            // "Encrypted" ciphertext
            return text
                .Split('\r', '\n')
                .Select(Convert.FromBase64String)
                .Where(a => a.Length > 0)
                .Select(a => Challenge18.CtrEncodeDecode(a, _keyBytes))
                .ToArray();
        }

        public static byte[] CrackXor(byte[][] cipherTexts)
        {
            // We're treating decrypting as nothing more than applying a XOR; we deduced the value
            byte[] xor = new byte[cipherTexts.Max(a => a.Length)];

            // First pass to come up with candidates for the XOR
            for (int i = 0; i < xor.Length; i++)
            {
                var candidates = (from candidate in Enumerable.Range(0x00, 0x100)
                                  let scoreSum = cipherTexts
                                         .Where(x => x.Length > i)
                                         .Select(z => Score((byte)(z[i] ^ candidate)))
                                         .Sum()
                                  select (candidate, scoreSum)).OrderByDescending(x => x.scoreSum);

                xor[i] = (byte)candidates.First().candidate;
            }

            return xor;
        }

        public static void Run()
        {
            // "Encrypted" ciphertext
            byte[][] cipherTexts = CtrEncodeBase64Strings(Utility.GetResource("19.txt"));

            // We're treating decrypting as nothing more than applying a XOR; we deduced the value
            byte[] xor = CrackXor(cipherTexts);

            // Second pass, we looked at the output and tweaked it
            xor[0] = 0xCA;
            xor[1] = 0x88 ^ 0x07;
            xor[2] = 0xF4;
            xor[3] = 0x9a ^ 0x07;
            xor[4] = 0xD9;
            xor[5] = 0x89;
            xor[6] = 0x09 ^ 0x02;
            xor[7] = 0xAB;
            xor[8] = 0x74;
            xor[9] = 0xF5;
            xor[10] = 0x3A ^ 0x07;
            xor[11] = 0x75;
            xor[12] = 0x05;
            xor[13] = 0xF5;
            xor[14] = 0x09;
            xor[15] = 0xC8;
            xor[16] = 0x35;
            xor[17] = 0xEB;
            xor[18] = 0xCF;
            xor[19] = 0x1E;
            xor[20] = 0x3E;
            xor[21] = 0x8A;
            xor[22] = 0x43;
            xor[23] = 0x4D ^ 0x02;
            xor[24] = 0x54;
            xor[25] = 0x9C;
            xor[26] = 0xB9;
            xor[27] = 0xF4;
            xor[28] = 0xAA ^ 0x02;
            xor[29] = 0x00 ^ 0x02;
            xor[30] = 0xC6 ^ 0x1D;
            xor[31] = 0xFC ^ 0x16;
            xor[32] = 0x47 ^ ('x' ^ 'h');
            xor[33] = 0x99 ^ ('p' ^ 'e');
            xor[34] = 0x85 ^ ('l' ^ 'a');
            xor[35] = 0x84 ^ ('s' ^ 'd');
            xor[36] = 0x21 ^ ('l' ^ 'n');
            xor[37] = 0xc0 ^ ('n' ^ ',');

            byte[][] xoredCipherText = cipherTexts
                .Select(x => Challenge2.XorBytes(x, xor))
                .ToArray();

            for(int i = 0; i < xoredCipherText.Length; i++)
            {
                Console.WriteLine($"#{i:d2}: {Encoding.ASCII.GetString(xoredCipherText[i])}");
            }
        }
    }
}
