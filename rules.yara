rule http_url_hunter
{
    strings:
        $url = /http?:\/\/([\w\.-]+)([\/\w \.-]*)/
	$ip = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
		
    condition:
       $url or $ip
}

rule interesting_strings_hunter
{
	
	strings:
    	$a1 = "http" nocase ascii wide
        $a2 = "agent" nocase ascii wide
        $a3 = ".dll" nocase ascii wide
        $a4 = ".exe" nocase ascii wide
        $a5 = "select" nocase ascii wide
        $a6 = "antivirus" nocase ascii wide
        $a7 = "cmd.exe" nocase ascii wide
        $a8 = "powershell" nocase ascii wide
        $a9 = "AutoOpen" nocase ascii wide
        $a9_2 = "AutoClose" nocase ascii wide
        $a10 = "password" nocase ascii wide
        $a11 = "username" nocase ascii wide
        $a12 = "admin" nocase ascii wide
        $a13 = "HKEY" nocase ascii wide
        $a14 = "This program cannot" ascii wide xor
        $a15 = "Win32_" nocase ascii wide

    condition:
       any of them
}

