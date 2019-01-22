using System.IO;

namespace AuthenticationSdkTests.util
{
    public static class Constants
    {
        //Comment the below keysDirectory (Configured for Travis CI)
        public static readonly string ResourceFolderPath = $"src{Path.DirectorySeparatorChar}References{Path.DirectorySeparatorChar}AuthenticationSdk{Path.DirectorySeparatorChar}AuthenticationSdkTests{Path.DirectorySeparatorChar}Resource";
        
        //Uncomment below keysDirectory
        //public static readonly string ResourceFolderPath = $"..{Path.DirectorySeparatorChar}..{Path.DirectorySeparatorChar}Resource";
    }
}
