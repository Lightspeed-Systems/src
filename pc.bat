cd \content\src
perlapp --exe %1.exe --icon c:\content\src\ipmagic.ico --info CompanyName="Lightspeed Systems Corporation";FileDescription="Total Traffic Control utility program";FileVersion=8.02.0.0;InternalName=%1.exe;OriginalFilename=%1.exe;ProductName="Total Traffic Control";ProductVersion=8.02.0.0 %1.cmd
move %1.exe \content\bin
