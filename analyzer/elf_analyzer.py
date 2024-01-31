from elftools.elf.elffile import ELFFile
import sys


def analyze_elf(file_path):
    try:
        with open(file_path, 'rb') as f:
            elf_file = ELFFile(f)

            # Get ELF header information
            print(f"ELF Header:")
            print(f"  Entry point address: {hex(elf_file.header.e_entry)}")
            print(f"  Number of program headers: {elf_file.header.e_phnum}")
            print(f"  Section header offset: {hex(elf_file.header.e_shoff)}")

            # Print information about each program header
            print("\nProgram Headers:")
            for segment in elf_file.iter_segments():
                print(f"  Type: {segment.header.p_type}")
                print(f"  Offset: {hex(segment.header.p_offset)}")
                print(f"  Virtual Address: {hex(segment.header.p_vaddr)}")
                print(f"  Physical Address: {hex(segment.header.p_paddr)}")
                print(f"  File Size: {segment.header.p_filesz}")
                print(f"  Memory Size: {segment.header.p_memsz}")
                print(f"  Flags: {hex(segment.header.p_flags)}")
                print(f"  Alignment: {segment.header.p_align}")
                print("\n")

            # Symbol analysis
            print("\nSymbol Table:")
            for section in elf_file.iter_sections():
                if section.name.startswith('.symtab'):
                    for symbol in section.iter_symbols():
                        print(f"  Name: {symbol.name}")
                        print(f"  Address: {hex(symbol.entry.st_value)}")
                        print(f"  Size: {symbol.entry.st_size}")
                        print(f"  Type: {symbol.entry.st_info.type}")
                        print("\n")

            # Dynamic section analysis
            print("\nDynamic Sections:")
            for section in elf_file.iter_sections():
                if section.name.startswith('.dynamic'):
                    for tag in section.iter_tags():
                        print(f"  Tag: {tag.entry.d_tag}")
                        print(f"  Value: {hex(tag.entry.d_val)}")
                        print("\n")

            # Strings table analysis
            print("\nStrings Table:")
            for section in elf_file.iter_sections():
                if section.name.startswith('.strtab'):
                    strings = section.iter_strings()
                    for offset, string in strings:
                        print(f"  Offset: {hex(offset)} - String: {string}")

    except Exception as e:
        print(f"Error analyzing ELF file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 elf_analyzer.py '/Users/Kate/Desktop/analyzer/elf-Linux-ARM64-bash'")
    else:
        file_path = sys.argv[1]
        analyze_elf(file_path)
