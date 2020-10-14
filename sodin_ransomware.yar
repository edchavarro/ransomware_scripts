/*
   YARA Rule Set
   Author: Eduardo Chavarro|@echavarro
   Date: 2020-10-14
   Identifier: Looking for SODIN samples
*/

rule sodin_ransomware{
meta: 
	identifier = "Samples collected related to SODIN Ransomware"

strings:
	$s1 = "expand 32-byte kexpand 16-byte k" ascii 
	$s2 = ".exe" wide
	$s3 = "ServicesActive" wide
	$s4 = "__ProviderArchitecture" wide
	$s5 = "Double run not allowed!" wide
	$s6 = "vmcompute.exe" wide
	$s7 = "vmms.exe" wide
	$s8 = "vmwp.exe" wide
	$s9 = "svchost.exe" wide
	$s10 = "\\?\\" wide

condition:
      (uint16(0) == 0x5A4D) and (filesize > 50KB or filesize < 300KB) and (all of them)
}

