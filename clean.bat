forfiles /p .vs\ /m ipch /c "cmd /c if @isdir==TRUE rd /s /q @file" /s

rd /s /q "Bins"

rd /s /q "Example\x86"
rd /s /q "Example\x64"

rd /s /q "Tests\x86"
rd /s /q "Tests\x64"
