param (
    [Parameter(Mandatory=$true)]
    [string]$version,
    
    [Parameter(Mandatory=$false)]
    [string]$message = ""
)

# Check if git is installed
try {
    $gitVersion = git --version
    Write-Host "Using $gitVersion"
} catch {
    Write-Host "Error: Git is not installed or not in your PATH. Please install Git and try again." -ForegroundColor Red
    exit 1
}

# Check if we're in a git repository
if (-not (Test-Path ".git")) {
    Write-Host "Error: This doesn't appear to be a git repository. Please run this script from the root of your plugin repository." -ForegroundColor Red
    exit 1
}

# Ensure version starts with 'v'
if (-not $version.StartsWith("v")) {
    $version = "v" + $version
}

# Extract version without 'v' for the PHP file
$phpVersion = $version.Substring(1)

# Validate version format (should be x.y.z)
if (-not ($phpVersion -match '^\d+\.\d+\.\d+$')) {
    Write-Host "Error: Version must be in the format x.y.z (e.g., 1.6.1)" -ForegroundColor Red
    exit 1
}

# Check if the tag already exists
$existingTags = git tag -l $version
if ($existingTags) {
    Write-Host "Error: Tag $version already exists. Please choose a different version." -ForegroundColor Red
    exit 1
}

# Update version in main plugin file
$pluginFile = "aqm-formidable-spam-blocker.php"
if (-not (Test-Path $pluginFile)) {
    Write-Host "Error: Plugin file $pluginFile not found." -ForegroundColor Red
    exit 1
}

$content = Get-Content $pluginFile -Raw
$newContent = $content -replace '(Version:\s*)([0-9]+\.[0-9]+\.[0-9]+)', "`$1$phpVersion"
Set-Content -Path $pluginFile -Value $newContent -NoNewline

Write-Host "Updated version in $pluginFile to $phpVersion" -ForegroundColor Green

# Commit the version change
git add $pluginFile
if ([string]::IsNullOrEmpty($message)) {
    $commitMessage = "Bump version to $phpVersion"
} else {
    $commitMessage = "Bump version to $phpVersion: $message"
}

git commit -m $commitMessage
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to commit version change." -ForegroundColor Red
    exit 1
}

Write-Host "Committed version change with message: $commitMessage" -ForegroundColor Green

# Create and push the tag
git tag -a $version -m "Release $version"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to create tag $version." -ForegroundColor Red
    exit 1
}

Write-Host "Created tag $version" -ForegroundColor Green

# Push the tag
git push origin $version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to push tag $version to origin." -ForegroundColor Red
    exit 1
}

Write-Host "Pushed tag $version to origin" -ForegroundColor Green

# Push the commit
git push
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to push commit to origin." -ForegroundColor Red
    exit 1
}

Write-Host "Pushed commit to origin" -ForegroundColor Green

Write-Host "`n=== Release Process Started ===" -ForegroundColor Cyan
Write-Host "Version updated to $phpVersion and tag $version pushed to GitHub."
Write-Host "GitHub Actions will automatically create a release with a downloadable ZIP file."
Write-Host "This process may take a few minutes to complete."
Write-Host "You can check the status at: https://github.com/JustCasey76/aqm-plugins/actions"
Write-Host "Once complete, the release will be available at: https://github.com/JustCasey76/aqm-plugins/releases"
Write-Host "=== Release Process Started ===`n" -ForegroundColor Cyan
