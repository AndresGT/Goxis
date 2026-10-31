param(
    [Parameter(Mandatory = $true)] [string] $AdminToken,
    [Parameter(Mandatory = $true)] [string] $ViewerToken,
    [string] $BaseUrl = 'http://127.0.0.1:8080'
)

$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
$prefix = "$BaseUrl/api/public"

function Assert-Status([string] $Name, [int] $Actual, [int] $Expected) {
    if ($Actual -ne $Expected) {
        throw "$Name devolvió HTTP $Actual; se esperaba HTTP $Expected."
    }
    Write-Host "OK  $Name -> HTTP $Actual" -ForegroundColor Green
}

function Get-Status([string] $Uri, [hashtable] $Headers = @{}) {
    $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers -SkipHttpErrorCheck -TimeoutSec 8
    return [int] $response.StatusCode
}

Assert-Status 'lectura pública' (Get-Status "$prefix/") 200
Assert-Status 'ruta privada sin credencial' (Get-Status "$prefix/private") 401
Assert-Status 'ruta admin con rol admin' (Get-Status "$prefix/admin" @{ Authorization = "Bearer $AdminToken" }) 200
Assert-Status 'ruta admin con rol viewer' (Get-Status "$prefix/admin" @{ Authorization = "Bearer $ViewerToken" }) 403

Assert-Status 'rate limit solicitud 1' (Get-Status "$prefix/rate-limited") 200
Assert-Status 'rate limit solicitud 2' (Get-Status "$prefix/rate-limited") 200
Assert-Status 'rate limit solicitud 3' (Get-Status "$prefix/rate-limited") 429

$slowUri = "$prefix/queued"
$queueClient = [System.Net.Http.HttpClient]::new()
try {
	$firstTask = $queueClient.GetAsync($slowUri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
	Start-Sleep -Milliseconds 250
	$secondTask = $queueClient.GetAsync($slowUri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
	Start-Sleep -Milliseconds 250
	$rejected = $queueClient.GetAsync($slowUri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
	Assert-Status 'cola llena' ([int] $rejected.StatusCode) 503
	$firstResponse = $firstTask.GetAwaiter().GetResult()
	$secondResponse = $secondTask.GetAwaiter().GetResult()
	Assert-Status 'petición activa termina' ([int] $firstResponse.StatusCode) 200
	Assert-Status 'petición en cola termina' ([int] $secondResponse.StatusCode) 200
} finally {
	$queueClient.Dispose()
}

$session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$login = Invoke-WebRequest -Uri "$BaseUrl/_goxis/admin/login" -Method Post `
    -ContentType 'application/json' -Body '{"username":"admin","password":"admin"}' `
    -WebSession $session -SkipHttpErrorCheck -TimeoutSec 8
Assert-Status 'login del panel' ([int] $login.StatusCode) 200

$cookieUri = [uri] "$BaseUrl/_goxis/admin/"
$cookie = $session.Cookies.GetCookies($cookieUri) | ForEach-Object { "$($_.Name)=$($_.Value)" }
if (-not $cookie) { throw 'El login no devolvió la cookie de sesión del panel.' }
$client = [System.Net.Http.HttpClient]::new()
$client.DefaultRequestHeaders.Add('Cookie', ($cookie -join '; '))
$client.DefaultRequestHeaders.Add('Accept', 'text/event-stream')
try {
    $response = $client.GetAsync("$BaseUrl/_goxis/admin/api/events", [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    Assert-Status 'conexión SSE del panel' ([int] $response.StatusCode) 200
    if ($response.Content.Headers.ContentType.MediaType -ne 'text/event-stream') {
        throw "El panel respondió con Content-Type inesperado: $($response.Content.Headers.ContentType)."
    }
    Write-Host 'OK  el panel entrega actualizaciones por SSE' -ForegroundColor Green
    $response.Dispose()
} finally {
    $client.Dispose()
}

Write-Host "`nSmoke check completado. Para revisar SSE en el navegador: $BaseUrl/_goxis/admin" -ForegroundColor Cyan
