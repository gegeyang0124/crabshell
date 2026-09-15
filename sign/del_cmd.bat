@echo off
setlocal enabledelayedexpansion

for %%F in (*.zipa) do (
    del  %%F 
    echo delete zipa finish
)

for %%F in (*.idsig) do (
    del  %%F 
    echo delete idsig finish
)
