# shell.ps1 - Execute a shell command passed via Invoke-Expression
param (
    [string]$Command
)

# Execute the command
if ($Command) {
    Invoke-Expression -Command $Command
} else {
    Write-Output "No command provided."
}
