@echo off
cd /d "%~dp0"
rem Builds CleanMemory.exe with the C# compiler that ships with Windows (.NET Framework 4.x).
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /optimize /win32manifest:app.manifest /out:CleanMemory.exe CleanMemory.cs
