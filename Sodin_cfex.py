#By Eduardo Chavarro @echavarro
# Script to extract the json configuration file for sodin ransomware samples
#
# Usage:    python Sodin_cfex.py sodin_sample_path
#
#Example: 
#python Sodin_cfex.py /mnt/c/Danger/File/8a197f6b33463b849090850f28bdf15effaf638ef52403f84eda759a66ea88a5
#Analyzing SODIN sample  /mnt/c/Danger/File/8a197f6b33463b849090850f28bdf15effaf638ef52403f84eda759a66ea88a5
#**************************************************
#Suspicious Header
#.o9yjcf
#|-- Virtual Size : 0xc800
#|-- VirutalAddress : 0x13000
#|-- SizeOfRawData : 0xc800
#|-- PointerToRawData : 0x10600
#|-- Characteristics : 0xc0000040
#
#Key:  B8xyWt7BwaQb8qm1LGVQkVn9cJrJmeQG
#Configuration parameters from section  .o9yjcf  have been saved to file: 
# /mnt/c/Danger/File/8a197f6b33463b849090850f28bdf15effaf638ef52403f84eda759a66ea88a5.json
#**************************************************

import pefile
import sys
from Crypto.Cipher import ARC4

offset = 0x0
size = 0x0

pe = pefile.PE(sys.argv[1])

print("Analyzing SODIN sample ", sys.argv[1])
print("*" * 50)

for section in pe.sections:
    name = section.Name.decode().rstrip('\x00')
    if name not in ('.text','.rdata','.data','.reloc'):
        print("Suspicious Header")
        print(section.Name.decode().rstrip('\x00') + "\n|-- Virtual Size : " + hex(section.Misc_VirtualSize) + "\n|-- VirutalAddress : " + hex(section.VirtualAddress) + "\n|-- SizeOfRawData : " + hex(section.SizeOfRawData) + "\n|-- PointerToRawData : " + hex(section.PointerToRawData) + "\n|-- Characteristics : " + hex(section.Characteristics)+'\n')
        offset = section.VirtualAddress
        size = section.SizeOfRawData 
        key = pe.get_memory_mapped_image()[offset:offset+0x20]
        print('Key: ',key.decode("utf-8"))
        cfgData = pe.get_memory_mapped_image()[offset+0x28:offset+size]
        cipher = ARC4.new(key)
        msg = cipher.decrypt(cfgData)
        data=msg.__str__().split('\\x')[0]
        with open(sys.argv[1]+'.json', 'w') as outfile:
            outfile.write(data[2::])
        print("Configuration parameters from section ", name, " have been saved to file: ", sys.argv[1]+'.json')

print("*" * 50)