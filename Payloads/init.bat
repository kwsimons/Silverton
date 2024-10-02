rem Initialization script, called before all payloads are invoked

rem Prevent .NET from crashing on telemetry output
set DOTNET_CLI_TELEMETRY_OPTOUT=1

rem Prevent .NET MSBuild random failures
set DOTNET_EnableWriteXorExecute=0

rem Prevent first time installation message
set DOTNET_NOLOGO=1

rem Allow for .NET programs on older versions to run using the latest installed .NET version (useful when loading <8.0 programs via dotnet 8.0)
set DOTNET_ROLL_FORWARD=LatestMajor

rem Load the configurable environment variables
call %~dp0\config.bat
rem call %~dp0\config.local.bat

rem Allow for .NET programs to find our installed .NET (useful when loading <8.0 programs via dotnet 8.0)
set DOTNET_ROOT=%DOTNET_DIRECTORY%

rem Used by launcher scripts
set DOTNET_PATH=%DOTNET_DIRECTORY%\dotnet.exe