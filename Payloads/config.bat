rem Configuration script, sets environment variables used by payload scripts

rem Absolute path to the .NET SDK directory
set DOTNET_DIRECTORY=D:\xbox\dotnet

rem Absolute path to the MSBUILD project file that invokes the Launcher
set MSBUILD_XML_PATH=D:\xbox\payloads\initialize.xml

rem Absolute path to the MSBUILD project file that invokes the Launcher
set LAUNCHER_DIRECTORY=D:\xbox\payloads\launcher

rem Log level used by the Launcher
rem 0 = FATAL, 1 = ERROR, 2 = WARN, 3 = INFO, 4 = DEBUG, 5 = TRACE
set LOG_LEVEL=1