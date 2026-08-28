$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask=([System.WindowsRuntimeSystemExtensions].GetMethods()|?{$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'})[0]
function Await($t,$rt){$m=$asTask.MakeGenericMethod($rt);$nt=$m.Invoke($null,@($t));$nt.Wait(-1)|Out-Null;$nt.Result}
[Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime]|Out-Null
[Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]|Out-Null
[Windows.Graphics.Imaging.BitmapDecoder,Windows.Graphics,ContentType=WindowsRuntime]|Out-Null
$p='C:\Users\sunyuxiao\AppData\Local\Temp\qoder-computer-use-images\6c35b30f\img-1787669380588379300-826045.png'
$f=Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($p)) ([Windows.Storage.StorageFile])
$s=Await ($f.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$d=Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($s)) ([Windows.Graphics.Imaging.BitmapDecoder])
$b=Await ($d.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
$e=[Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
$r=Await ($e.RecognizeAsync($b)) ([Windows.Media.Ocr.OcrResult])
foreach($l in $r.Lines){$minX=($l.Words|%{$_.BoundingRect.X}|Measure-Object -Minimum).Minimum;$minY=($l.Words|%{$_.BoundingRect.Y}|Measure-Object -Minimum).Minimum;$maxX=($l.Words|%{($_.BoundingRect.X+$_.BoundingRect.Width)}|Measure-Object -Maximum).Maximum;$maxY=($l.Words|%{($_.BoundingRect.Y+$_.BoundingRect.Height)}|Measure-Object -Maximum).Maximum;if($minY -gt 450){'{0} [X:{1}-{2} Y:{3}-{4}]' -f $l.Text,[int]$minX,[int]$maxX,[int]$minY,[int]$maxY}}
