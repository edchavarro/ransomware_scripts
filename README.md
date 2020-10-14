# ransomware_scripts
A collection of scripts for Ransomware Analysis and identification


#Sodin_cfex.py:

Script to extract the json configuration file for sodin ransomware samples

Usage:    python Sodin_cfex.py sodin_sample_path

Example: 
python Sodin_cfex.py /mnt/c/Danger/File/8a197f6b33463b849090850f28bdf15effaf638ef52403f84eda759a66ea88a5
Analyzing SODIN sample  /mnt/c/Danger/File/8a197f6b33463b849090850f28bdf15effaf638ef52403f84eda759a66ea88a5
**************************************************
Suspicious Header
.o9yjcf
|-- Virtual Size : 0xc800
|-- VirutalAddress : 0x13000
|-- SizeOfRawData : 0xc800
|-- PointerToRawData : 0x10600
|-- Characteristics : 0xc0000040

Key:  B8xyWt7BwaQb8qm1LGVQkVn9cJrJmeQG
Configuration parameters from section  .o9yjcf  have been saved to file: 
 /mnt/c/Danger/File/8a197f6b33463b849090850f28bdf15effaf638ef52403f84eda759a66ea88a5.json
**************************************************

#Sodin_Ransomware.yar

   YARA Rule Set
   Author: Eduardo Chavarro|@echavarro
   Date: 2020-10-14
   Identifier: Looking for SODIN samples
   
