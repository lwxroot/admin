$Date = Get-Date -f yyy.MM.dd-HH-mm
Get-EventLog -LogName Security -After (Get-Date).AddHours(-32) | ?{(4779,4778,4800,4801) -contains $_.EventID} | %{
(new-object -Type PSObject -Property @{
Время = $_.TimeGenerated
IP_адресс = if($_.EventID -eq 4779 -or $_.EventID -eq 4778) {$_.Message -replace '(?smi).*Адрес клиента:\s+([^\s]+)\s+.*','$1'} else {"-"}
Пользователь = $_.Message -replace '(?smi).*Имя учетной записи:\s+([^\s]+)\s+.*','$1'
Хост = if($_.EventID -eq 4779 -or $_.EventID -eq 4778) {$_.Message -replace '(?smi).*Имя клиента:\s+([^\s]+)\s+.*','$1'} else {"-"}
Статус = if($_.EventID -eq 4779) {"<-- Отключился от сервера (закрыл RDP)"}
    elseif($_.EventID -eq 4778) {"--> ПОДКЛЮЧИЛСЯ"} 
    elseif($_.EventID -eq 4800) {"ОТОШЁЛ (Блокировка экрана)"} 
    elseif($_.EventID -eq 4801) {"ВЕРНУЛСЯ (Экран разблокирован)"}
})
} | sort Время -Descending | Select Время, Статус, Пользователь, IP_адресс, Хост | Format-Table | Out-File "Q:\Отдел IT\Вход сотрудников\10.11.13.7_loGin__$Date.txt"