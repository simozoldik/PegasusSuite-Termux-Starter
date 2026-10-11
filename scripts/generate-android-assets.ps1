# =============================================================================
# Pegasus Suite - Android brand asset generator
# -----------------------------------------------------------------------------
# Generates launcher icons (legacy + round + adaptive foreground) and splash
# screens into android/app/src/main/res from the canonical PWA icons.
#
# Source artwork : frontend/icons/icon-512.png  (full-bleed launcher logo)
# Brand color    : #5B2D86
#
# Run: powershell -ExecutionPolicy Bypass -File scripts\generate-android-assets.ps1
# =============================================================================
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$root    = Split-Path -Parent $PSScriptRoot
$res     = Join-Path $root 'android\app\src\main\res'
$iconPath = Join-Path $root 'frontend\icons\icon-512.png'
$brand   = [System.Drawing.Color]::FromArgb(255, 0x5B, 0x2D, 0x86)

if (-not (Test-Path $iconPath)) { throw "Source icon not found: $iconPath" }
$source = [System.Drawing.Image]::FromFile($iconPath)

function New-Canvas([int]$w, [int]$h, [System.Drawing.Color]$bg) {
    $bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode   = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    if ($bg.A -gt 0) { $g.Clear($bg) } else { $g.Clear([System.Drawing.Color]::Transparent) }
    return @($bmp, $g)
}

function Save-Png($bmp, $path) {
    $dir = Split-Path -Parent $path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
}

# --- density tables -----------------------------------------------------------
$launcher = @{ 'mdpi'=48; 'hdpi'=72; 'xhdpi'=96; 'xxhdpi'=144; 'xxxhdpi'=192 }
$fg       = @{ 'mdpi'=108; 'hdpi'=162; 'xhdpi'=216; 'xxhdpi'=324; 'xxxhdpi'=432 }

# --- 1. legacy square launcher icons (full-bleed, brand background) -----------
foreach ($d in $launcher.Keys) {
    $s = $launcher[$d]
    $c = New-Canvas $s $s $brand
    $bmp = $c[0]; $g = $c[1]
    # logo inset ~10% so the square icon keeps a brand margin
    $inner = [int]($s * 0.84)
    $off = [int](($s - $inner) / 2)
    $g.DrawImage($source, $off, $off, $inner, $inner)
    $g.Dispose()
    Save-Png $bmp (Join-Path $res "mipmap-$d\ic_launcher.png")
    $bmp.Dispose()
}

# --- 2. round launcher icons (circular clip, brand background) ----------------
foreach ($d in $launcher.Keys) {
    $s = $launcher[$d]
    $c = New-Canvas $s $s $brand
    $bmp = $c[0]; $g = $c[1]
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddEllipse(0, 0, $s, $s)
    $g.SetClip($path)
    $inner = [int]($s * 0.84)
    $off = [int](($s - $inner) / 2)
    $g.DrawImage($source, $off, $off, $inner, $inner)
    $g.Dispose()
    Save-Png $bmp (Join-Path $res "mipmap-$d\ic_launcher_round.png")
    $bmp.Dispose()
    $path.Dispose()
}

# --- 3. adaptive foreground (transparent, logo inside 66% safe zone) ----------
# Android adaptive icons show only the centre 66x66dp of the 108x108dp canvas,
# so the visible logo must fit inside that safe zone.
foreach ($d in $fg.Keys) {
    $s = $fg[$d]
    $c = New-Canvas $s $s ([System.Drawing.Color]::Transparent)
    $bmp = $c[0]; $g = $c[1]
    $inner = [int]($s * 0.60)
    $off = [int](($s - $inner) / 2)
    $g.DrawImage($source, $off, $off, $inner, $inner)
    $g.Dispose()
    Save-Png $bmp (Join-Path $res "mipmap-$d\ic_launcher_foreground.png")
    $bmp.Dispose()
}

# --- 4. splash screens (brand background + centred logo) ----------------------
# Capacitor SplashScreen plugin uses the density/portrait/landscape variants.
$splashes = @(
    @{ p='drawable\splash.png';                w=480;  h=320  },
    @{ p='drawable-land-mdpi\splash.png';      w=480;  h=320  },
    @{ p='drawable-land-hdpi\splash.png';      w=800;  h=480  },
    @{ p='drawable-land-xhdpi\splash.png';     w=1280; h=720  },
    @{ p='drawable-land-xxhdpi\splash.png';    w=1600; h=960  },
    @{ p='drawable-land-xxxhdpi\splash.png';   w=1920; h=1280 },
    @{ p='drawable-port-mdpi\splash.png';      w=320;  h=480  },
    @{ p='drawable-port-hdpi\splash.png';      w=480;  h=800  },
    @{ p='drawable-port-xhdpi\splash.png';     w=720;  h=1280 },
    @{ p='drawable-port-xxhdpi\splash.png';    w=960;  h=1600 },
    @{ p='drawable-port-xxxhdpi\splash.png';   w=1280; h=1920 }
)
foreach ($sp in $splashes) {
    $c = New-Canvas $sp.w $sp.h $brand
    $bmp = $c[0]; $g = $c[1]
    $logo = [int]([Math]::Min($sp.w, $sp.h) * 0.30)
    $x = [int](($sp.w - $logo) / 2)
    $y = [int](($sp.h - $logo) / 2)
    $g.DrawImage($source, $x, $y, $logo, $logo)
    $g.Dispose()
    Save-Png $bmp (Join-Path $res $sp.p)
    $bmp.Dispose()
}

$source.Dispose()
Write-Host "Android brand assets generated under $res"
