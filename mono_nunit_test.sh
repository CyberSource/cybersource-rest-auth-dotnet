wget -nc https://nuget.org/nuget.exe

mozroots --import --sync



echo "[INFO] install NUnit runners via NuGet"

wget -nc https://nuget.org/nuget.exe

mozroots --import --sync

mono nuget.exe install src/References/AuthenticationSdk/AuthenticationSdk/packages.config -o packages



echo "[INFO] Install NUnit runners via NuGet"

mono nuget.exe install NUnit.ConsoleRunner -Version 3.8.0 -OutputDirectory packages 



echo "[INFO] Build the solution and run the unit test"

xbuild src/References/AuthenticationSdk/AuthenticationSdk.sln && \

    mono ./packages/NUnit.ConsoleRunner.3.8.0/tools/nunit3-console.exe src/References/AuthenticationSdk/AuthenticationSdkTests/bin/Debug/AuthenticationSdkTests.dll