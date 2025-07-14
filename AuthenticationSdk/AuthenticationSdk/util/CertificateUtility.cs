using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AuthenticationSdk.util
{
    /// <summary>
    /// Utility class providing methods that can process certificates
    /// </summary>
    public class CertificateUtility
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Validates that the given file path exists and is not empty.
        /// </summary>
        /// <param name="filePath">The file path to validate.</param>
        /// <param name="pathType">A description of the path type (e.g., "Input file").</param>
        /// <exception cref="ArgumentException">If the path is null or empty.</exception>
        /// <exception cref="IOException">If the file does not exist.</exception>
        public static void ValidatePathAndFile(string filePath, string pathType)
        {
            if (string.IsNullOrEmpty(filePath.Trim()))
            {
                logger.Error(pathType + " path cannot be null or empty.");
                throw new ArgumentException(pathType + " path cannot be null or empty.");
            }

            // Normalize Windows-style paths that start with a slash before the drive letter
            string normalizedPath = filePath;
            if (Path.DirectorySeparatorChar == '\\' && Regex.IsMatch(normalizedPath, @"^/[A-Za-z]:.*"))
            {
                normalizedPath = normalizedPath.Substring(1);
            }

            string path = normalizedPath;
            if (!File.Exists(path))
            {
                logger.Error($"{pathType} does not exist: {path}");
                throw new IOException($"{pathType} does not exist: {path}");
            }
            if ((File.GetAttributes(path) & FileAttributes.Directory) == FileAttributes.Directory)
            {
                logger.Error($"{pathType} does not have valid file: {path}");
                throw new IOException($"{pathType} does not have valid file: {path}");
            }
            try
            {
                using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.Read))
                {
                    // File is readable
                }
            }
            catch (Exception)
            {
                logger.Error($"{pathType} is not readable: {path}");
                throw new IOException($"{pathType} is not readable: {path}");
            }
        }

        public static X509Certificate2Collection LoadCertificatesFromPemFile(string certificateFilePath)
        {
            byte[] certBytes = File.ReadAllBytes(certificateFilePath);

            var collection = new X509Certificate2Collection();
            collection.Import(certBytes);

            return collection;
        }

        public static X509Certificate2 SearchCertificateByAlias(X509Certificate2Collection certificates, string mleKeyAlias)
        {
            if (certificates == null || string.IsNullOrEmpty(mleKeyAlias))
            {
                return null;
            }

            foreach (var cert in certificates)
            {
                try
                {
                    string subjectDN = cert.Subject;

                    string[] dnParts = subjectDN.Split(',');
                    foreach (var part in dnParts)
                    {
                        var trimmedPart = part.Trim();
                        if (trimmedPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                        {
                            string commonName = trimmedPart.Substring(3); // Remove "CN="
                            if (string.Equals(mleKeyAlias, commonName, StringComparison.OrdinalIgnoreCase))
                            {
                                return cert;
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    logger.Warn("Error parsing certificate subject DN: " + e.Message);
                }
            }

            return null;
        }
    }
}
