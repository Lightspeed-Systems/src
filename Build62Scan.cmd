REM Scan and Scan utilities
cd \content\src
perlapp --exe scan62.exe --icon c:\content\src\scan.ico --info CompanyName="Lightspeed Systems Corporation";FileDescription="Security Agent Scanner utility";FileVersion=6.02.00.0;InternalName=scan.exe;OriginalFilename=scan.exe;ProductName="Security Agent";ProductVersion=6.02.00.0 scan.pl
move scan62.exe \content\bin

del \SecurityAgent\Setup\scan62.exe
copy \content\bin\scan62.exe \SecurityAgent\Setup\scan62.exe /y

perlapp --exe Update62.exe --icon c:\content\src\Update.ico --info CompanyName="Lightspeed Systems Corporation";FileDescription="Security Agent Update utility";FileVersion=6.02.00.0;InternalName=Update.exe;OriginalFilename=Update.exe;ProductName="Security Agent";ProductVersion=6.02.00.0 Update6.pl
move Update62.exe \content\bin
del \SecurityAgent\Setup\Update62.exe
copy \content\bin\Update62.exe \SecurityAgent\Setup\Update62.exe

perlapp --exe SigDesign62.exe --icon c:\content\src\SigDesign.ico --info CompanyName="Lightspeed Systems Corporation";FileDescription="Security Agent Signature Design utility";FileVersion=6.02.00.0;InternalName=SigDesign.exe;OriginalFilename=SigDesign.exe;ProductName="Security Agent";ProductVersion=6.02.00.0 SigDesign.pl
move SigDesign62.exe \content\bin
del \SecurityAgent\Setup\SigDesign62.exe
copy \content\bin\SigDesign62.exe \SecurityAgent\Setup\SigDesign62.exe

cd \SecurityAgent\Setup

attrib scan62.exe -r
attrib update62.exe -r
attrib sigdesign62.exe -r

scan -u

REM copy the new stuff to my own security agent directory
copy scan62.exe "C:\Program Files\Lightspeed Systems\SecurityAgent\scan62.exe" /y
copy Update62.exe "C:\Program Files\Lightspeed Systems\SecurityAgent\Update62.exe" /y
copy SigDesign62.exe "C:\Program Files\Lightspeed Systems\SecurityAgent\SigDesign62.exe" /y
