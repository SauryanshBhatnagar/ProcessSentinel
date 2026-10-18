@echo off
set PATH=C:\MinGW\bin;%PATH%
if not exist build mkdir build
if not exist web mkdir web

echo Compiling SQLite (C)...
gcc -c third_party\sqlite-amalgamation-3470000\sqlite3.c -DSQLITE_OMIT_LOAD_EXTENSION -o build\sqlite3.o
if errorlevel 1 goto fail

echo Compiling ProcessSentinel (C++)...
g++ -std=c++11 -Iinclude -Ithird_party\sqlite-amalgamation-3470000 -c src\process_monitor.cpp -o build\process_monitor.o
if errorlevel 1 goto fail
g++ -std=c++11 -Iinclude -Ithird_party\sqlite-amalgamation-3470000 -c src\detector.cpp -o build\detector.o
if errorlevel 1 goto fail
g++ -std=c++11 -Iinclude -Ithird_party\sqlite-amalgamation-3470000 -c src\database.cpp -o build\database.o
if errorlevel 1 goto fail
g++ -std=c++11 -Iinclude -Ithird_party\sqlite-amalgamation-3470000 -c src\html_report.cpp -o build\html_report.o
if errorlevel 1 goto fail
g++ -std=c++11 -Iinclude -Ithird_party\sqlite-amalgamation-3470000 -c src\main.cpp -o build\main.o
if errorlevel 1 goto fail

echo Linking...
g++ -o ProcessSentinel.exe build\main.o build\process_monitor.o build\detector.o build\database.o build\html_report.o build\sqlite3.o -lpsapi -liphlpapi -lws2_32 -ladvapi32 -lshell32
if errorlevel 1 goto fail

echo.
echo Build successful: ProcessSentinel.exe
echo Run it with: ProcessSentinel.exe
goto end

:fail
echo.
echo Build failed. Check the error messages above.
exit /b 1

:end
