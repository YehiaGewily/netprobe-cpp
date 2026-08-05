# Generates resources/netprobe.ico — a multi-resolution Windows app icon
# matching the NetProbe UI accent palette. No external tools required; uses
# .NET System.Drawing to render and emits a standard ICO container with PNG
# payloads for each size.
#
# Usage:  pwsh tools/make_icon.ps1

Add-Type -AssemblyName System.Drawing
# System.Drawing.Imaging is a namespace inside System.Drawing.dll, not a
# separate assembly — Add-Type'ing it on PowerShell 7+ prints a spurious
# "cannot find path" error even though the namespace loads fine. Skip it.

$repoRoot       = Resolve-Path "$PSScriptRoot/.."
$outPath        = Join-Path $repoRoot "resources/netprobe.ico"
$embeddedHeader = Join-Path $repoRoot "src/ui/EmbeddedIcon.hpp"
$sizes          = @(16, 32, 48, 64, 128, 256)
# Sizes copied into the embedded C++ header for runtime use via
# glfwSetWindowIcon (16/32/48 covers every WM's preferred slot).
$embeddedSizes  = @(16, 32, 48)

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

function Get-RgbaPixels {
    param([System.Drawing.Bitmap]$bmp)
    $size = $bmp.Width
    $rect = New-Object System.Drawing.Rectangle 0, 0, $size, $size
    $data = $bmp.LockBits($rect,
        [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $stride = $data.Stride
    $bgra = New-Object byte[] ($stride * $size)
    [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bgra, 0, $bgra.Length)
    $bmp.UnlockBits($data)

    # System.Drawing.Format32bppArgb stores B, G, R, A on little-endian.
    # GLFW wants R, G, B, A top-down. Swap channels and strip the stride
    # padding so the output is exactly width*height*4 bytes.
    $rgba = New-Object byte[] ($size * $size * 4)
    for ($y = 0; $y -lt $size; $y++) {
        for ($x = 0; $x -lt $size; $x++) {
            $src = $y * $stride + $x * 4
            $dst = ($y * $size + $x) * 4
            $rgba[$dst]     = $bgra[$src + 2]  # R
            $rgba[$dst + 1] = $bgra[$src + 1]  # G
            $rgba[$dst + 2] = $bgra[$src + 0]  # B
            $rgba[$dst + 3] = $bgra[$src + 3]  # A
        }
    }
    return ,$rgba
}

# Render every size and stash the PNG bytes (for .ico) plus raw RGBA (for the
# embedded C++ header).
$pngPayloads = @()
$rgbaPayloads = @{}
foreach ($size in $sizes) {
    $bmp = Render-Icon -size $size
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngPayloads += ,$ms.ToArray()
    $ms.Dispose()
    if ($embeddedSizes -contains $size) {
        $rgbaPayloads[$size] = Get-RgbaPixels -bmp $bmp
    }
    $bmp.Dispose()
}

# Write the embedded RGBA arrays as a single header. Pure data, no functions,
# so dropping a new icon is just rerunning this script.
$headerLines = New-Object System.Collections.Generic.List[string]
$headerLines.Add("// Auto-generated by tools/make_icon.ps1 — do not edit by hand.")
$headerLines.Add("// Raw, top-down, non-premultiplied RGBA pixel data ready to feed into")
$headerLines.Add("// glfwSetWindowIcon for the title bar and taskbar.")
$headerLines.Add("#pragma once")
$headerLines.Add("")
$headerLines.Add("namespace ui {")
$headerLines.Add("")
foreach ($size in $embeddedSizes) {
    $bytes = $rgbaPayloads[$size]
    $headerLines.Add("    inline constexpr int kEmbeddedIcon${size}Size = $size;")
    $headerLines.Add("    inline constexpr unsigned char kEmbeddedIcon${size}Pixels[$($bytes.Length)] = {")
    $sb = New-Object System.Text.StringBuilder
    $sb.Append("        ") | Out-Null
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $sb.AppendFormat("0x{0:x2}", $bytes[$i]) | Out-Null
        if ($i -ne $bytes.Length - 1) { $sb.Append(",") | Out-Null }
        if (($i % 16) -eq 15 -and $i -ne $bytes.Length - 1) {
            $headerLines.Add($sb.ToString())
            $sb.Clear() | Out-Null
            $sb.Append("        ") | Out-Null
        } elseif ($i -ne $bytes.Length - 1) {
            $sb.Append(" ") | Out-Null
        }
    }
    if ($sb.Length -gt 8) { $headerLines.Add($sb.ToString()) }
    $headerLines.Add("    };")
    $headerLines.Add("")
}
$headerLines.Add("} // namespace ui")
[System.IO.File]::WriteAllLines($embeddedHeader, $headerLines)

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
Write-Host "Wrote $embeddedHeader (RGBA arrays for sizes: $($embeddedSizes -join ', '))"
