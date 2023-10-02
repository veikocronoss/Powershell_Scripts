$arrS = @('!','@','#','$','%','^','&','*','(',')','+')
Function ACV($char){
    if($char -lt 10) {
        return $true
    }elseif([char]$char -imatch '^[A-Za-z0-9]+$'){
        return $true
    }elseIf($arrS -contains [char]$char){
        return $true
    }else{
        return $false
    }
}

Function Get-Hash ($ui,$lim){
    $pw = $null
    $SAS = [System.IO.MemoryStream]::new()
    $wr = [System.IO.StreamWriter]::new($SAS)
    $wr.write($ui)
    $wr.Flush()
    $SAS.Position = 0

    $hv = Get-FileHash -Algorithm SHA512 -InputStream $SAS | Select-Object Hash
    $hv = $hv.Hash
    $hs = $hv.ToString().ToCharArray()
    
    For($i = 0; $i -le $hv.Length; $i++){
        $h = [System.Convert]::ToInt32($hs[$i-1]+$hs[$i],16)

        $check = ACV -char $h
        While($check -ne $true){
            $m = $h
            if(($m -ge 10) -and ($m -le 32)){ $m += 10 }
            if($m -gt 122){
                if(($m % 2) -eq 0){
                    $m = $m / 2
                }else{
                    $m = $m / 2
                    $m = [Math]::Round([int]$m)
                }
            }else{
                $m += 1
            }
            $h = [int]$m
            $check = ACV -char $h
        }
        if($h -lt 10){
            $pw = $pw + $h
        }else{
            $pw = $pw + [char]$h
        }

        If($pw.Length -ge $lim){break}
    }

    Return $pw
}

Function Get-Pass ($limit){
    $pw = Get-Hash -ui $userinput -lim $limit
    $fr = $true
    While($fr){
        $u = [regex]::Matches($pw,'[A-Z]').count
        $l = [regex]::Matches($pw,'[a-z]').count
        $n = [regex]::Matches($pw,'[0-9]').count
        ForEach($c in $pw.ToCharArray()){
            If($arrS -contains $c){
                $s++
            }
        }
        If(($u -ge 2) -and ($l -ge 2) -and ($n -ge 2) -and ($s -ge 2)){
            $fr = $false
        }else{
            $pw = Get-Hash -ui $pw -lim $limit
        }
    }
    Return $pw
}

$userinput = Read-Host "Give me a String: "
[int]$userlimit = Read-Host "Give me a number between 8 and 30: "
if($userlimit -lt 8){ 
    $userlimit = 8
    Write-Host "Not high enough of a limit. Defaulting to 8 Characters"
}
if($userlimit -gt 30){ 
    $userlimit = 30
    Write-Host "Too large of a password. Dropping to 30 characters"
}


$returned = Get-Pass -limit $userlimit
Write-Host $returned