@echo off
setlocal enabledelayedexpansion

set YYYYmmdd=%date:~0,4%%date:~5,2%%date:~8,2%
echo %YYYYmmdd%
set hhmm=%time:~0,2%%time:~3,2%
set hhmm=%hhmm: =0%
echo  %hhmm%
set time24=%YYYYmmdd%%hhmm%
echo  %time24%

for %%F in (*.zipa) do (
    set fileName=%%~nF
    echo %%F to !fileName!
    set outFileName=!fileName!_!YYYYmmdd!!hhmm!.apk
    echo !outFileName!
)

pause