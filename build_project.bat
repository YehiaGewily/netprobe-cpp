@echo off
setlocal

echo Searching for Visual Studio 2022 installation...

:: Try Community
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    echo Found VS 2022 Community
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    goto :Build
)

:: Try Enterprise
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    echo Found VS 2022 Enterprise
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    goto :Build
)

:: Try Professional
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    echo Found VS 2022 Professional
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    goto :Build
)

echo.
echo Error: Could not find Visual Studio 2022 (Community, Enterprise, or Professional).
echo Please run this from the "Developer Command Prompt for VS 2022".
exit /b 1

:Build
echo.
echo [0/3] Cleaning previous build artifacts...
if exist build rmdir /s /q build
if exist build (
    echo Error: Could not delete 'build' directory.
    echo Please CLOSE any open files in 'build\' - e.g. CMakeCache.txt - and try again.
    exit /b 1
)

echo Environment initialized. Building NetProbe...
echo.

:: Configure
echo [1/3] Configuring CMake...
cmake -B build -S . -G "Visual Studio 17 2022" -A x64
if %ERRORLEVEL% NEQ 0 (
    echo Configuration failed.
    exit /b %ERRORLEVEL%
)

:: Build
echo [2/3] Compiling Release build...
cmake --build build --config Release
if %ERRORLEVEL% NEQ 0 (
    echo Build failed.
    exit /b %ERRORLEVEL%
)

:: Test
echo [3/3] Running tests...
ctest --test-dir build --build-config Release --output-on-failure
if %ERRORLEVEL% NEQ 0 (
    echo Tests failed.
    exit /b %ERRORLEVEL%
)

echo.
echo Build Successful! 
echo Executable located at: build\Release\NetProbe.exe
echo.
pause
