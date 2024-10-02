rem Configuration script, sets environment variables used by payload scripts

rem Absolute path to the .NET SDK executable
set DOTNET_PATH=%USERPROFILE%\Desktop\xbox\dotnet\dotnet.exe

rem Absolute path to the MSBUILD project file that invokes the Launcher
set MSBUILD_XML_PATH=%USERPROFILE%\source\repos\ShellServer\Silverton\payloads\initialize.xml

rem Absolute path to the directory that contains the launcher dll
set LAUNCHER_DIRECTORY=%USERPROFILE%\source\repos\ShellServer\Silverton\bin\Release\netstandard2.0

rem Log level used by the Launcher
rem 0 = FATAL, 1 = ERROR, 2 = WARN, 3 = INFO, 4 = DEBUG, 5 = TRACE
set LOG_LEVEL=3