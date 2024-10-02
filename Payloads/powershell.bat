@echo off
rem Launches pwsh.exe via our custom launcher

rem Perform initialization
call %~dp0\init.bat

rem The current working directory to use when invoking the command
set CWD=C:\\

rem The command we want to run
set COMMAND=%LAUNCHER_DIRECTORY%\..\pwsh\pwsh.exe

rem Execute the command (via our custom launcher)
%DOTNET_PATH% msbuild /nologo "%MSBUILD_XML_PATH%" ^
		-property:LauncherDirectory="%LAUNCHER_DIRECTORY%" ^
		-property:LogLevel="%LOG_LEVEL%" ^
		-property:WorkingDirectory="%CWD%" ^
		-property:Command="%COMMAND%"