import sys
import os
import pefile
from capstone import *

def print_banner():
    """Prints the tool banner."""
    banner = r"""

 ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
 ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
 ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝ 
 ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗ 
  ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
   ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

    """
    print(banner)
    print("--- DLL/SYS to ASM Disassembler v1.0 ---\n")

def disassemble_file(file_path):
    """Disassembles a PE file and saves output to .asm file."""
    # Remove quotes if user dragged and dropped the file
    file_path = file_path.replace('"', '').strip()
    
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' does not exist.")
        return

    try:
        print(f"[*] Analyzing: {file_path}...")
        pe = pefile.PE(file_path)
        
        # Determine architecture: 0x8664 is x64, otherwise x86
        if pe.FILE_HEADER.Machine == 0x8664:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_32)

        output_file = os.path.splitext(file_path)[0] + ".asm"
        
        with open(output_file, "w") as f:
            f.write(f"; Disassembled: {os.path.basename(file_path)}\n\n")
            
            for section in pe.sections:
                # 0x20000000 checks if the section contains executable code
                if section.Characteristics & 0x20000000:
                    code = section.get_data()
                    address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    
                    f.write(f"\n; --- Section: {section.Name.decode(errors='ignore').strip()} ---\n")
                    
                    for insn in md.disasm(code, address):
                        f.write(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}\n")
        
        print(f"[+] Success! Assembly saved to: {output_file}")

    except Exception as e:
        print(f"[-] Error processing file: {e}")

def main():
    print_banner()
    print("--- Type 'exit' or press Ctrl+C to quit ---\n")
    
    while True:
        # Получаем ввод от пользователя
        user_input = input(">> Enter path to binary: ").strip()
        
        # Проверка на выход
        if user_input.lower() in ['exit', 'quit']:
            print("[*] Exiting...")
            break
            
        # Удаляем кавычки, если путь был перетащен мышкой
        file_path = user_input.replace('"', '').strip()
        
        if file_path:
            disassemble_file(file_path)
            print("-" * 50) # Разделитель для удобства чтения
        else:
            print("[!] Please provide a valid file path.")

if __name__ == "__main__":
    main()
