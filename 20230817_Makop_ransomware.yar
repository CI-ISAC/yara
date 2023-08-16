import "pe"
rule PuffedUp{
meta:
author= "@luc4m"
date= "2023–03–12"
modified= "2023–03–12"
hash= "e245f8d129e8eadb00e165c569a14b71"
description="puffedup tool in makop ransomware toolkit"
tlp="CLEAR"
strings:
$main_1 = { 00 72 [4] 28 [4] 00 72 [4] 0A 72 [4] 28 [4] 00 29 }
$main_2 = { 0B 07 28 [4] 80 [4] 28 [4] 00 2A }
$sash_3 = { 72 [4] 0C [4] 72 [4] 0D 28 [4] 13 08 2C 06 }
$sash_4 = { 16 FE 01 13 0C 11 0C 2C 17 11 08 }
$sash_5 = { 1c 0D 00 20 [4] 28 [4] 00 00 DE 00 }
condition:
uint16(0) == 0x5a4d
and pe.imports("mscoree.dll")
and ( 2 of ($sash_*) or 1 of ($main_*) )
}
rule ARestore{
meta:
author= "@luc4m"
date= "2023–03–12"
modified= "2023–03–12"
hash= "7f86b67ac003eda9d2929c9317025013"
description="ARestore in makop ransomware toolkit"
tlp="CLEAR"
strings:
$junk_1= { 2B 09 28 [4] 14 16 9A 26 16 2D F9 14 2A }
$obj_1= { 38 [4] 26 20 [4] 38 [4] FE [4] 38 [4] 20 [4] 20 [4] 59 9C 20 [4] FE [4] 28 [4] 38 }
$obj_2= { FE [4] 20 [4] FE [4] 9C 20 [4] 38 [4] 12 }
$string_1 = "ADLogic" nocase
$string_2 = "GetUserFromGroupAsync" nocase
$string_3 = "WriteResultAsync" nocase
$string_4 = "ParseLoginAsync" nocase
$string_5 = "GenerateCredentials" nocase
$string_6 = "GetUserAsync" nocase
$string_7 = "IsAuthenticated" nocase
condition:
uint16(0) == 0x5a4d
and pe.imports("mscoree.dll")
and ( (1 of ($junk_*) or 1 of ($obj_*)) and 3 of ($string_*) )
}