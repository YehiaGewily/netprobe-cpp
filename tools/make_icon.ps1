# Generates resources/netprobe.ico — a multi-resolution Windows app icon
# matching the NetProbe UI accent palette. No external tools required; uses
# .NET System.Drawing to render and emits a standard ICO container with PNG
# payloads for each size.
#
# Usage:  pwsh tools/make_icon.ps1

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Drawing.Imaging

$repoRoot = Resolve-Path "$PSScriptRoot/.."
$outPath  = Join-Path $repoRoot "resources/netprobe.ico"
$sizes    = @(16, 32, 48, 64, 128, 256)

# Palette mirrors src/ui/GuiTheme.hpp so the icon reads as part of the UI.
$bgColor     = [System.Drawing.Color]::FromArgb(255, 13, 13, 18)   # near-black
$accentColor = [System.Drawing.Color]::FromArgb(255, 94, 106, 210) # #5E6AD2 violet
$accentSoft  = [System.Drawing.Color]::FromArgb(96,  94, 106, 210) # ring outline
$dotColor    = [System.Drawing.Color]::FromArgb(255, 240, 240, 245)

function New-RoundedPath {
    param([System.Drawing.Rectangle]$rect, [int]$radius)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $diameter = $radius * 2
    $path.AddArc($rect.X, $rect.Y, $diameter, $diameter, 180, 90)
    $path.AddArc($rect.Right - $diameter, $rect.Y, $diameter, $diameter, 270, 90)
    $path.AddArc($rect.Right - $diameter, $rect.Bottom - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()
    return $path
}

function Render-Icon {
    param([int]$size)
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    # Rounded-square background.
    $cornerRadius = [Math]::Max(2, [int]($size / 8))
    $rect = New-Object System.Drawing.Rectangle 0, 0, $size, $size
    $path = New-RoundedPath -rect $rect -radius $cornerRadius
    $bgBrush = New-Object System.Drawing.SolidBrush $bgColor
    $g.FillPath($bgBrush, $path)
    $bgBrush.Dispose()
    $path.Dispose()

    $center = $size / 2.0

    # Outer pulse ring (soft accent).
    $ringDiameter = $size * 0.72
    $ringRect = New-Object System.Drawing.RectangleF `
        (($center - $ringDiameter / 2.0), ($center - $ringDiameter / 2.0), $ringDiameter, $ringDiameter)
    $ringPen = New-Object System.Drawing.Pen $accentSoft, ([single]($size / 18.0))
    $g.DrawEllipse($ringPen, $ringRect)
    $ringPen.Dispose()

    # Solid accent core.
    $coreDiameter = $size * 0.42
    $coreRect = New-Object System.Drawing.RectangleF `
        (($center - $coreDiameter / 2.0), ($center - $coreDiameter / 2.0), $coreDiameter, $coreDiameter)
    $accentBrush = New-Object System.Drawing.SolidBrush $accentColor
    $g.FillEllipse($accentBrush, $coreRect)
    $accentBrush.Dispose()

    # Bright highlight dot in the center.
    $dotDiameter = [Math]::Max(2.0, $size * 0.16)
    $dotRect = New-Object System.Drawing.RectangleF `
        (($center - $dotDiameter / 2.0), ($center - $dotDiameter / 2.0), $dotDiameter, $dotDiameter)
    $dotBrush = New-Object System.Drawing.SolidBrush $dotColor
    $g.FillEllipse($dotBrush, $dotRect)
    $dotBrush.Dispose()

    $g.Dispose()
    return $bmp
}

# Render every size and stash the PNG bytes.
$pngPayloads = @()
foreach ($size in $sizes) {
    $bmp = Render-Icon -size $size
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngPayloads += ,$ms.ToArray()
    $ms.Dispose()
    $bmp.Dispose()
}

# Build the ICO container.
#   ICONDIR  (6 bytes):  reserved=0, type=1 (icon), count
#   ICONDIRENTRY (16 bytes each):  size, planes, bitcount, bytesInRes, offset
#   <image payloads>  (PNG per entry — supported since Vista)
$icoStream = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.BinaryWriter $icoStream

$writer.Write([uint16]0)
$writer.Write([uint16]1)
$writer.Write([uint16]$sizes.Count)

$entrySize = 16
$payloadOffset = 6 + $sizes.Count * $entrySize

for ($i = 0; $i -lt $sizes.Count; $i++) {
    $size = $sizes[$i]
    $payload = $pngPayloads[$i]
    # ICO encodes 256 as 0 in the byte-size fields.
    $w = if ($size -ge 256) { 0 } else { [byte]$size }
    $h = if ($size -ge 256) { 0 } else { [byte]$size }

    $writer.Write([byte]$w)
    $writer.Write([byte]$h)
    $writer.Write([byte]0)             # color count (0 = no palette)
    $writer.Write([byte]0)             # reserved
    $writer.Write([uint16]1)           # color planes
    $writer.Write([uint16]32)          # bits per pixel
    $writer.Write([uint32]$payload.Length)
    $writer.Write([uint32]$payloadOffset)

    $payloadOffset += $payload.Length
}

foreach ($payload in $pngPayloads) {
    $writer.Write($payload)
}

$resourcesDir = Split-Path $outPath -Parent
if (-not (Test-Path $resourcesDir)) {
    New-Item -ItemType Directory -Path $resourcesDir -Force | Out-Null
}
[System.IO.File]::WriteAllBytes($outPath, $icoStream.ToArray())
$bytesWritten = $icoStream.Length
$writer.Dispose()
$icoStream.Dispose()

Write-Host "Wrote $outPath ($bytesWritten bytes, $($sizes.Count) sizes: $($sizes -join ', '))"
