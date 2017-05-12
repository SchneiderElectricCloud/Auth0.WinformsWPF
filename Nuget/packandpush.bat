@echo off
@cd /d "%~dp0"

echo info: Setup MSBuild environment
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Professional\Common7\Tools\VsMSBuildCmd.bat"

echo info: Build Auth0 WinformsWPF Solution
msbuild.exe "..\Auth0.WinformsWPF.sln" /p:Configuration=Release /t:Rebuild
if ERRORLEVEL 1 (
    echo error: Failed to build Auth0.WinformsWPF solution
    goto EXIT
)

echo info: --------------------------------------------
echo info: Pack NuGet specs...
for /f %%a IN ('dir /b *.nuspec') do (
	nuget pack "%%a"
)

echo info: --------------------------------------------
echo info: Push NuGet packages...
for /f %%b IN ('dir /b *.nupkg') do (
	nuget push "%%b" -ApiKey e1377f9f-71aa-4166-a861-fb3f64f84bef -Source https://arcfmsolution.myget.org/F/productteam/api/v2/package
)

echo info: --------------------------------------------
echo info: Delete NuGet packages...
for /f %%c IN ('dir /b *.nupkg') do (
	del "%%c"
)

:EXIT
pause