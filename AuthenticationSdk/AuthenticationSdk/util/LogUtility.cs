using NLog;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthenticationSdk.util
{
    public class LogUtility
    {
        private static Dictionary<string, string> sensitiveTags = new Dictionary<string, string>();

        private static void LoadSensitiveDataConfiguration()
        {
            sensitiveTags.Clear();

            int sensitiveTagsCount = SensitiveDataConfigurationType.sensitiveTags.Length;

            for (int i = 0; i < sensitiveTagsCount; i++)
            {
                string tagName = SensitiveDataConfigurationType.sensitiveTags[i].tagName;
                string pattern = SensitiveDataConfigurationType.sensitiveTags[i].pattern;
                string replacement = SensitiveDataConfigurationType.sensitiveTags[i].replacement;

                if (!string.IsNullOrEmpty(pattern))
                {
                    pattern = $"\\\"{tagName}\\\":\\\"{pattern}\\\"";
                }
                else
                {
                    pattern = $"\\\"{tagName}\\\":\\\".+\\\"";
                }

                replacement = $"\"{tagName}\":\"{replacement}\"";

                sensitiveTags.Add(pattern, replacement);
            }
        }

        public static string MaskSensitiveData(string str)
        {
            LoadSensitiveDataConfiguration();

            foreach (KeyValuePair<string, string> tag in sensitiveTags)
            {
                str = Regex.Replace(str, tag.Key, tag.Value);
            }

            return str;
        }

        public static bool IsMaskingEnabled(Logger logger)
        {
            return logger.Factory.Configuration.Variables["enableMasking"].ToString().ToLower().Contains("true");
        }

        public static string ConvertDictionaryToString(Dictionary<string, string> dict)
        {
            var stringBuilder = new StringBuilder();

            foreach (KeyValuePair<string, string> kvp in dict)
            {
                stringBuilder.Append($"{kvp.Key} = {kvp.Value}\n");
            }

            return stringBuilder.ToString();
        }
    }
}
