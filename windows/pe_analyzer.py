import pefile
import sys

def analyze_pe(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Print DOS header information
        print("DOS Header:")
        print("  Magic: {}".format(hex(pe.DOS_HEADER.e_magic)))
        print("  Address of New EXE Header: {}".format(hex(pe.DOS_HEADER.e_lfanew)))

        # Print COFF header information
        print("\nCOFF Header:")
        print("  Machine: {}".format(hex(pe.FILE_HEADER.Machine)))
        print("  Number of Sections: {}".format(pe.FILE_HEADER.NumberOfSections))
        print("  Time Date Stamp: {}".format(hex(pe.FILE_HEADER.TimeDateStamp)))
        print("  Pointer to Symbol Table: {}".format(hex(pe.FILE_HEADER.PointerToSymbolTable)))
        print("  Number of Symbols: {}".format(pe.FILE_HEADER.NumberOfSymbols))
        print("  Size of Optional Header: {}".format(pe.FILE_HEADER.SizeOfOptionalHeader))

        # Print Optional header information
        print("\nOptional Header:")
        print("  Image Base: {}".format(hex(pe.OPTIONAL_HEADER.ImageBase)))
        print("  Section Alignment: {}".format(pe.OPTIONAL_HEADER.SectionAlignment))
        print("  File Alignment: {}".format(pe.OPTIONAL_HEADER.FileAlignment))
        print("  Size of Image: {}".format(pe.OPTIONAL_HEADER.SizeOfImage))
        print("  Size of Headers: {}".format(pe.OPTIONAL_HEADER.SizeOfHeaders))

        # Print information about each section
        print("\nSection Headers:")
        for section in pe.sections:
            print("  Name: {}".format(section.Name.decode('utf-8').rstrip('\x00')))
            print("  Virtual Address: {}".format(hex(section.VirtualAddress)))
            print("  Virtual Size: {}".format(hex(section.Misc_VirtualSize)))
            print("  Size of Raw Data: {}".format(hex(section.SizeOfRawData)))
            print("  Pointer to Raw Data: {}".format(hex(section.PointerToRawData)))
            print("  Characteristics: {}".format(hex(section.Characteristics)))
            print("\n")

        # Exported functions analysis
        print("\nExported Functions:")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print("  Name: {}".format(exp.name.decode('utf-8') if exp.name else 'N/A'))
                print("  Address: {}".format(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)))
                print("\n")

    except Exception as e:
        print("Error analyzing PE file: {}".format(e))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pe_analyzer.py '/Users/Kate/Desktop/windows/win_app.exe'")
    else:
        file_path = sys.argv[1]
        analyze_pe(file_path)
