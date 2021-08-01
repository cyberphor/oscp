(Get-NetTcpConnection).OwningProcess | ForEach-Object { Get-Process -Id $_ | Select-Object -ExpandProperty Path } | Sort-Object | Get-Unique
