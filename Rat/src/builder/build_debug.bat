@echo off
setlocal enabledelayedexpansion

REM Initialize variables
set help=0
set output=
set sectname=

REM Parse arguments
:parse_args
if "%~1"=="" goto args_done
if "%~1"=="-h" (
    set help=1
) else if "%~1"=="--help" (
    set help=1
) else if "%~1"=="-output" (
    set output=%~2
    shift
) else if "%~1"=="-sectname" (
    set sectname=%~2
    shift
) else (
    echo Unknown argument: %~1
    exit /b 1
)
shift
goto parse_args

:args_done

REM Display help if requested
if %help%==1 (
    echo Usage: %~nx0 [-h] [--help] [-output value] [-sectname value]
    echo.
    echo Options:
    echo   -h, --help          Show this help message and exit
    echo   -output value       Specify the output file or directory
    echo   -sectname value     Specify the section name
    exit /b 0
)

REM Check if required arguments are provided
if "%output%"=="" (
    echo Error: -output is required
    exit /b 1
)
if "%sectname%"=="" (
    echo Error: -sectname is required
    exit /b 1
)

echo Output: %output%
echo Section Name: %sectname%

echo [*] running cargo
cargo build --package Rat --bin Rat
echo [*] adding section to file
python ../scripts/add_section.py -d data -f ../../target/debug/Rat.exe -o  %output%.exe -s %sectname%
echo [*] done

endlocal


