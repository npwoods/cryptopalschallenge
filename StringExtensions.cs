using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CryptoPalsChallenge
{
    public static class StringExtensions
    {
        public static string TrimEndSingle(this string @this, params char[] trimChars)
        {
            return @this.Length > 0 && trimChars.Contains(@this[@this.Length - 1])
                ? @this.Substring(0, @this.Length - 1)
                : @this;
        }
    }
}
