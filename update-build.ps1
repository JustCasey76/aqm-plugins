# Script to update the build directory with the latest files
# This is for testing purposes only and should not be committed to the repository

# Create build directory if it doesn't exist
if (-not (Test-Path "build")) {
    New-Item -ItemType Directory -Path "build"
}

# Copy all files except those that should be excluded
$filesToCopy = Get-ChildItem -Path "." -Exclude @(
    ".git",
    ".github",
    ".gitignore",
    ".gitattributes",
    "build",
    "create-release.ps1",
    "update-build.ps1",
    "docs",
    "*.zip"
)

foreach ($file in $filesToCopy) {
    if ($file.PSIsContainer) {
        # It's a directory, copy it recursively
        Copy-Item -Path $file.FullName -Destination "build\$($file.Name)" -Recurse -Force
    } else {
        # It's a file, copy it
        Copy-Item -Path $file.FullName -Destination "build\$($file.Name)" -Force
    }
}

Write-Host "Build directory updated with the latest files." -ForegroundColor Green
