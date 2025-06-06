# Get the current directory path
$CurrentDirectory = Get-Location

# List the files and folders in the current directory
$DirectoryContents = Get-ChildItem -Path $CurrentDirectory

# Output the current directory and its contents
Write-Output "Current Directory: $($CurrentDirectory.Path)"
Write-Output "Contents:"
$DirectoryContents | ForEach-Object {
    Write-Output $_.Name
}
