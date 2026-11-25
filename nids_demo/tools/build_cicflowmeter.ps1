<#
build_cicflowmeter.ps1 — Tai ma nguon va build CICFlowMeter 4.0 (Java) cho JDK hien dai (da thu JDK 21).

Ban build san khong chay voi JDK 21 (Gradle 4.2 cu) va jnetpcap khong co tren Maven Central, nen script
tu: clone ma nguon -> tai thu vien tu Maven Central -> bien dich bang javac (--release 8) -> dong goi.
Ket qua: tools_ext\CICFlowMeter-4.0\bin\cfm.bat  (app tu dong dung file nay).

Yeu cau: git, java, javac (JDK) deu co trong PATH; may co internet.
Cach chay (trong thu muc nids_demo):
    powershell -ExecutionPolicy Bypass -File tools\build_cicflowmeter.ps1
#>
param(
    [string]$ExtDir = (Join-Path $PSScriptRoot '..\tools_ext'),
    [string]$DistName = 'CICFlowMeter-4.0'
)
$ErrorActionPreference = 'Stop'

foreach ($exe in 'git', 'java', 'javac', 'jar') {
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
        throw "Khong tim thay '$exe' trong PATH. Hay cai Git va JDK roi thu lai."
    }
}

$ExtDir = [System.IO.Path]::GetFullPath($ExtDir)
New-Item -ItemType Directory -Force $ExtDir | Out-Null
$src = Join-Path $ExtDir 'CICFlowMeter'

Write-Host '==> (1/4) Clone ma nguon CICFlowMeter'
if (-not (Test-Path (Join-Path $src 'build.gradle'))) {
    git clone --depth 1 https://github.com/ahlashkari/CICFlowMeter.git $src
} else {
    Write-Host '    (da co, bo qua)'
}

Write-Host '==> (2/4) Tai thu vien tu Maven Central'
$lib = Join-Path $src 'lib'
New-Item -ItemType Directory -Force $lib | Out-Null
$M = 'https://repo1.maven.org/maven2'
$jars = @(
    'org/slf4j/slf4j-api/1.7.25/slf4j-api-1.7.25.jar',
    'org/slf4j/slf4j-simple/1.7.25/slf4j-simple-1.7.25.jar',
    'org/apache/commons/commons-lang3/3.6/commons-lang3-3.6.jar',
    'org/apache/commons/commons-math3/3.5/commons-math3-3.5.jar',
    'commons-io/commons-io/2.5/commons-io-2.5.jar',
    'com/google/guava/guava/23.6-jre/guava-23.6-jre.jar',
    'org/jfree/jfreechart/1.5.0/jfreechart-1.5.0.jar',
    'org/apache/tika/tika-core/1.17/tika-core-1.17.jar',
    'nz/ac/waikato/cms/weka/weka-stable/3.6.14/weka-stable-3.6.14.jar'
)
foreach ($j in $jars) {
    $dst = Join-Path $lib (Split-Path $j -Leaf)
    if (-not (Test-Path $dst)) {
        Write-Host "    tai $(Split-Path $j -Leaf)"
        Invoke-WebRequest "$M/$j" -OutFile $dst -UseBasicParsing
    }
}
Copy-Item (Join-Path $src 'jnetpcap\win\jnetpcap-1.4.r1425\jnetpcap.jar') $lib -Force

Write-Host '==> (3/4) Bien dich bang javac (--release 8)'
$classes = Join-Path $src 'build\classes'
if (Test-Path $classes) { Remove-Item $classes -Recurse -Force }
New-Item -ItemType Directory -Force $classes | Out-Null
$srcList = Join-Path $src 'sources.txt'
Get-ChildItem (Join-Path $src 'src\main\java') -Recurse -Filter *.java |
    Where-Object { $_.Name -ne 'CICFlowMeter.java' } |
    ForEach-Object { $_.FullName } | Set-Content $srcList -Encoding ascii
& javac --release 8 -encoding UTF-8 -cp (Join-Path $lib '*') -d $classes ('@' + $srcList)
if ($LASTEXITCODE -ne 0) { throw 'javac that bai' }
Copy-Item (Join-Path $src 'src\main\resources\*') $classes -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '==> (4/4) Dong goi ban phan phoi'
$dist = Join-Path $ExtDir $DistName
New-Item -ItemType Directory -Force (Join-Path $dist 'lib\native') | Out-Null
New-Item -ItemType Directory -Force (Join-Path $dist 'bin') | Out-Null
Push-Location $classes
try { & jar cf (Join-Path $dist 'lib\CICFlowMeter-4.0.jar') . } finally { Pop-Location }
Copy-Item (Join-Path $lib '*.jar') (Join-Path $dist 'lib') -Force
Copy-Item (Join-Path $src 'jnetpcap\win\jnetpcap-1.4.r1425\*.dll') (Join-Path $dist 'lib\native') -Force
Copy-Item (Join-Path $src 'LICENSE.txt') $dist -Force -ErrorAction SilentlyContinue

$cfm = @"
@echo off
rem CICFlowMeter 4.0 (che do dong lenh). Cach dung: cfm.bat <file pcap hoac thu muc> <thu muc output>
setlocal
set "APP_HOME=%~dp0.."
rem Npcap khong bat che do tuong thich WinPcap -> wpcap.dll nam trong System32\Npcap
set "PATH=%SystemRoot%\System32\Npcap;%PATH%"
set "JAVA_EXE=java"
if defined CFM_JAVA_HOME set "JAVA_EXE=%CFM_JAVA_HOME%\bin\java.exe"
"%JAVA_EXE%" -Djava.library.path="%APP_HOME%\lib\native" -cp "%APP_HOME%\lib\*" cic.cs.unb.ca.ifm.Cmd %*
endlocal
"@
Set-Content (Join-Path $dist 'bin\cfm.bat') $cfm -Encoding ascii

Write-Host ''
Write-Host "XONG. CICFlowMeter o: $dist"
Write-Host "Kiem tra:  & '$dist\bin\cfm.bat'  <file.pcap>  <thu_muc_out>"
