using System.Text;

namespace Silverton.Core.Build {

    public class MSBuild {

        // Escape a value so that it can be used as an MSBuild property value (eg `-Property:Key=Value`)
        public static string EscapeMSBuildPropertyValue(string propertyValue) {

            propertyValue = EscapedProperty(propertyValue);

            // Escape trailing backslashes as they escape the closing quotes
            if (propertyValue.EndsWith(@"\")) {
                propertyValue = propertyValue.TrimEnd('\\') + @"\\";
            }

            return propertyValue;
        }

        private static string EscapedProperty(string unescapedString) {
            if (unescapedString == null) {
                return "";
            }
            var sb = new StringBuilder();
            AppendEscapedString(sb, unescapedString);
            return sb.ToString();
        }

        // https://github.com/dotnet/msbuild/blob/d17ec720df6ea81145fe462834ba3a68aa19d766/src/Shared/EscapingUtilities.cs#L153
        private static char HexDigitChar(int x) {
            return (char)(x + (x < 10 ? '0' : ('a' - 10)));
        }

        // https://github.com/dotnet/msbuild/blob/d17ec720df6ea81145fe462834ba3a68aa19d766/src/Shared/EscapingUtilities.cs#L153
        private static void AppendEscapedChar(StringBuilder sb, char ch) {
            // Append the escaped version which is a percent sign followed by two hexadecimal digits
            sb.Append('%');
            sb.Append(HexDigitChar(ch / 0x10));
            sb.Append(HexDigitChar(ch & 0x0F));
        }

        // https://github.com/dotnet/msbuild/blob/d17ec720df6ea81145fe462834ba3a68aa19d766/src/Shared/EscapingUtilities.cs#L153
        private static void AppendEscapedString(StringBuilder sb, string unescapedString) {
            // Replace each unescaped special character with an escape sequence one
            for (int idx = 0; ;) {
                int nextIdx = unescapedString.IndexOfAny(s_charsToEscape, idx);
                if (nextIdx == -1) {
                    sb.Append(unescapedString, idx, unescapedString.Length - idx);
                    break;
                }

                sb.Append(unescapedString, idx, nextIdx - idx);
                AppendEscapedChar(sb, unescapedString[nextIdx]);
                idx = nextIdx + 1;
            }
        }

        // https://github.com/dotnet/msbuild/blob/d17ec720df6ea81145fe462834ba3a68aa19d766/src/Shared/EscapingUtilities.cs#L153
        private static readonly char[] s_charsToEscape = { '%', '*', '?', '@', '$', '(', ')', ';', '\'', '"' };
    }
}
