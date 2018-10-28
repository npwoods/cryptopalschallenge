using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace CryptoPalsChallenge
{
    /// <seealso cref="https://cryptopals.com/sets/3/challenges/20"/>
    /// <remarks>
    /// We already automated a lot of this for Challenge 19 - therefore, we will go for extra credit by using simulated
    /// annealing to decode the last bit.  While this isn't specified by the challenge, challenge #20 is particularly
    /// vague about what criteria constitutes success
    /// </remarks>
    public static class Challenge20
    {
        private static string[] DecodeWithXor(byte[][] cipherTexts, byte[] xor)
        {
            return cipherTexts
                .Select(x => Challenge2.XorBytes(x, xor))
                .Select(x => Encoding.ASCII.GetString(x))
                .ToArray();
        }

        private static IEnumerable<string> GetWords(string text)
        {
            return text.Split(' ', '-');
        }

        private static Regex _pseudoWord = new Regex(@"^[A-Za-z][a-z]*$", RegexOptions.Compiled);
        private static Regex _containsVowel = new Regex(@"A|E|I|O|U", RegexOptions.Compiled | RegexOptions.IgnoreCase);       

        private static int Score(byte[][] cipherTexts, byte[] xor)
        {
            int result = 0;
            foreach(var word in from line in DecodeWithXor(cipherTexts, xor)
                                from word in GetWords(line)
                                select word.TrimEndSingle('!', ',', '.', '?'))
            {
                if (Utility.IsWord(word))
                {
                    result += 100;
                }
                else if (_pseudoWord.IsMatch(word))
                {
                    result += 25;
                    if (_containsVowel.IsMatch(word))
                    {
                       result += 50;
                    }
                }

                // Score against caps after the beginning
                if (word.Length > 0 && char.IsLower(word[0]))
                {
                    for (int i = 1; i < word.Length; i++)
                    {
                        if (char.IsUpper(word, i))
                        {
                            result -= 10;
                            break;
                        }
                    }
                }
            }
            return result;
        }

        public static void Run()
        {
            // "Encrypted" ciphertext
            byte[][] cipherTexts = Challenge19.CtrEncodeBase64Strings(Utility.GetResource("20.txt"));

            // We're treating decrypting as nothing more than applying a XOR; we deduced the value
            byte[] xor = Challenge19.CrackXor(cipherTexts);

            // Anneal
            int score = Score(cipherTexts, xor);
            int[] tweakCounts = new[] { 1, 1, 1, 2, 2, 3, 3, 4, 5, 6 };

            int startTemp = 100000;
            for (int i = startTemp; i >= 0; i--)
            {
                byte[] newXor = Utility.Dupe(xor);
                int? firstPos = null;

                int tweakCount = tweakCounts[Utility.Random(tweakCounts.Length)];
                for (int j = 0; j < tweakCount; j++)
                {
                    int range = 7;
                    int pos = firstPos == null
                        ? Utility.Random(xor.Length)
                        : firstPos.Value + Utility.Random(range * 2 + 1) - range;
                    if (pos >= 0 && pos < xor.Length)
                    {
                        firstPos = pos;
                        bool setOrClear = Utility.Random(2) == 1;
                        byte mask = (byte)(1 << Utility.Random(8));

                        newXor[pos] |= (byte)(setOrClear ? mask : 0);
                        newXor[pos] &= (byte)~(setOrClear ? 0 : mask);
                    }
                }

                int newScore = Score(cipherTexts, newXor);
                if (newScore > score)
                {
                    xor = newXor;
                    score = newScore;
                }
            }

            string[] results = DecodeWithXor(cipherTexts, xor);
            for (int i = 0; i < results.Length; i++)
            {
                Console.WriteLine($"#{i:d2}: {results[i]}");
            }
        }
    }
}
