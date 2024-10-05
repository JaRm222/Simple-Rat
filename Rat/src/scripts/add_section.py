import pefile
import argparse
import struct
import math

#.\build_debug.bat -output Rat -sectname mysect

def section_to_bytes(section):
    """
    Convert a SectionStructure object to bytes for writing to a file.
    """
    return struct.pack(
        '8sIIIIIHHII',
        section.Name,
        section.Misc_VirtualSize,
        section.VirtualAddress,
        section.SizeOfRawData,
        section.PointerToRawData,
        section.PointerToRelocations,
        section.PointerToLinenumbers,
        section.NumberOfRelocations,
        section.NumberOfLinenumbers,
        section.Characteristics
    )

parser = argparse.ArgumentParser()

parser.add_argument("-f", "--file")
parser.add_argument("-o", "--output")
parser.add_argument("-d", "--data")
parser.add_argument("-s", "--section")

args = parser.parse_args()

pe = pefile.PE(args.file)
new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)

with open(args.data, "rb") as f:
    data = f.read()
f.close()

sect_name = args.section[:8].encode().ljust(8, b'\x00')


last_section = pe.sections[-1]

last_sec_end = last_section.VirtualAddress + last_section.Misc_VirtualSize

section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

new_va = math.ceil(last_sec_end / section_alignment) * section_alignment

new_section.Name = sect_name
new_section.Misc = len(data)
new_section.Misc_PhysicalAddress = len(data)
new_section.Misc_VirtualSize = len(data)
new_section.VirtualAddress = new_va
new_section.SizeOfRawData = len(data)
new_section.PointerToRawData = (pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData)
new_section.PointerToRelocations = 0x0
new_section.PointerToLinenumbers = 0x0
new_section.NumberOfRelocations = 0x0
new_section.NumberOfLinenumbers = 0x0
new_section.Characteristics = 0x40000000


pe.set_bytes_at_offset(pe.sections[-1].get_file_offset() + 0x28, section_to_bytes(new_section))
pe.sections.append(new_section)

pe.OPTIONAL_HEADER.SizeOfImage = new_va + len(data)

pe.FILE_HEADER.NumberOfSections += 1

pe.write(args.output)
pe.close()

with open(args.output, "ab")as f:
    f.write(data)
f.close()




