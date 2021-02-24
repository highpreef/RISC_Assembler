import getopt
import sys

####################################################
# OPEN FOR DEBUGGING!
####################################################

"""
Author: David Jorge
Course: Digital Systems Laboratory

This is a CLI Assembler for the RISC ISA used in Digital Systems Laboratory.
It takes in an input file with Assembly Instructions and assembles it down to machine code (in hex).

Size of ROM: 256 Bytes



###############################################################################
############################ ISA Green Card ###################################
###############################################################################
2 8-bit general purpose registers     A, B


mem_addr    Memory address in hex
rs, rt, rd  Source registers and Destination Register
procedure   Name of the target procedure (converted into an address in hex)


###############################################################################
########################### Instructions ######################################
###############################################################################
lw rs, mem_addr         rs = Mem[mem_addr]
sw rs, mem_addr         Mem[mem_addr] = rs
add rd, rs, rt          rd = rs + rt
sub rd, rs, rt          rd = rs - rt
mul rd, rs, rt          rd = rs * rt (if result is larger than 8 bits truncate)
sll rd, rs              rd = rs << 1
srl rd, rs              rd = rs >> 1
inc rd, rs              rd = rs + 1
dec rd, rs              rd = rs - 1
beq rs, rt, label       (rs == rt) ? goto label : goto next instruction
bgt rs, rt, label       (rs > rt) ? goto label : goto next instruction
blt rs, rt, label       (rs < rt) ? goto label : goto next instruction
goto label              unconditional jump to label
idle                    put cpu in idle state to wait for interrupt
jal label               unconditional jump to label, saves current PC
ra                      return to caller procedure
drf rs                  rs = Mem[rs]

## Gonna add mov, li, nand, and, or and xor instructions
##############################################################################


Interrupt Service Routines:
Mouse_Interrupt     ISR for mouse peripheral; Stored in 0xFF
Timer_Interrupt     ISR for timer; Stored in 0xFE


Main Procedure:
main                This procedure is called at the start


##########################################################
################# Example Assembly Code ##################
##########################################################
main:
lw A, 00 # load default value of MouseScroll into A
sw A, C0 # Update upper 8 LEDs with MouseScroll
lw A, 01 # Load default value of MouseX into A
sw A, D0 # Update 7seg with MouseX
lw A, 02 # Load default value of MouseY into A
sw A, D1 # Update 7seg with MouseY
lw A, 03 # Load default value of MouseStatus into A
sw A, C1 # Update lower 8 LEDs with MouseStatus
idle

Mouse_Interrupt:
lw A, A3 # load MouseScroll into A
sw A, C0 # Update upper 8 LEDs with MouseScroll
lw A, A1 # Load MouseX into A
sw A, D0 # Update 7seg with MouseX
lw A, A2 # Load MouseY into A
sw A, D1 # Update 7seg with MouseY
lw A, A0 # Load MouseStatus into A
sw A, C1 # Update lower 8 LEDs with MouseStatus
idle

Timer_Interrupt:
goto Mouse_Interrupt
idle
##########################################################
##########################################################


Use:
python Assembler.py [-i input_file] [-o output_file] [--rom_size size] [--verbose]

Opts:
    -i %input_file
        File that contains assembly instructions to be assembled down to machine code (in hex)
    -o %output_file
        File where assembled machine code is going to be exported to
    --rom_size %size
        Sets the target ROM size (in bytes)
    --verbose
        Gives more information on assembly process (debugging)
    
"""


class Instruction:
    """
    is class represents a single instruction. An instruction can have
    multiple arguments
    """

    def __init__(self, name, rs=None, rt=None, rd=None, mem_addr=None, label=None):
        self.name = name
        self.rs = rs
        self.rt = rt
        self.rd = rd
        self.mem_addr = mem_addr
        self.label = label

    def __len__(self):
        if self.name in ["lw", "sw", "beq", "bgt", "blt", "goto", "jal"]:
            return 2
        else:
            return 1


class Procedure:
    """
    This class represents a procedure (function) which is a collection
    of instructions, eg:

    Procedure1:
    ...
    ...

    Procedure2:
    ...
    ...
    """

    def __init__(self, procedure_name):
        self.procedure_name = procedure_name
        self.addr_in_ROM = 0x00
        self.instructions = []

    def __len__(self):
        num_bytes = 0
        for instruction in self.instructions:
            num_bytes += len(instruction)
        return num_bytes


def parse_stdin():
    """
    This function parses command line input into variables

    :return: input and output file names and a debug boolean
    """
    in_f = ""
    out_f = ""
    verbose = False
    size = 256

    try:
        opts, remaining = getopt.getopt(sys.argv[1:], "i:o:", ['verbose', 'rom_size='])
    except getopt.GetoptError:
        print("Use: python Assembler.py -i [input_file] -o [output_file] --verbose --rom_size [size]")
        sys.exit(1)
    for opt, arg in opts:
        if opt == "-i":
            in_f = arg
        elif opt == "-o":
            out_f = arg
        elif opt == "--rom_size":
            size = int(arg)
        elif opt == "--verbose":
            verbose = True

    if verbose:
        print("##########################################")
        print("############# Debugging! #################")
        print("##########################################\n")
        print("Input File: {}".format(in_f))
        print("Output File: {}".format(out_f))
        print("ROM size: {}\n".format(size))

    return in_f, out_f, verbose, size


def parse_assembly(file, debug=False):
    """
    This function parses the input assembly file into local variables

    :param file: Input file name
    :param debug: Used for debugging
    :return: A dictionary of procedure names to procedures
    """

    with open(file, 'r') as f:
        print("Reading assembly code...")
        curr_procedure = ""
        procedures = {}

        for num, lines in enumerate(f):
            line = lines.split()

            if len(line) > 0:
                arg = line[0]
                if debug:
                    print("Parsing line: {}".format(line))

                # Detect start of new procedure on encountering a label
                if arg not in ["lw", "sw", "add", "sub", "mul", "sll", "srl", "inc", "dec",
                               "beq", "bgt", "blt", "goto", "idle", "jal", "ra", "drf"] and arg[-1] == ":":
                    curr_procedure = arg[:-1]
                    procedures[curr_procedure] = Procedure(curr_procedure)

                # Detect load/store instructions
                elif arg in ["lw", "sw"]:
                    instruction = Instruction(name=arg, rs=line[1][:-1], rt=None, rd=None, mem_addr=line[2], label=None)
                    procedures[curr_procedure].instructions.append(instruction)

                # Detect basic arithmetic instructions
                elif arg in ["add", "sub", "mul"]:
                    instruction = Instruction(name=arg, rs=line[2][:-1], rt=line[3], rd=line[1][:-1], mem_addr=None,
                                              label=None)
                    procedures[curr_procedure].instructions.append(instruction)

                # Detect complex arithmetic instructions
                elif arg in ["sll", "srl", "inc", "dec"]:
                    instruction = Instruction(name=arg, rs=line[2], rt=None, rd=line[1][:-1], mem_addr=None, label=None)
                    procedures[curr_procedure].instructions.append(instruction)

                # Detect branch instructions
                elif arg in ["beq", "bgt", "blt"]:
                    instruction = Instruction(name=arg, rs=line[1][:-1], rt=line[2][:-1], rd=None, mem_addr=None,
                                              label=line[3])
                    procedures[curr_procedure].instructions.append(instruction)

                # Detect no argument instructions
                elif arg in ["ra", "idle"]:
                    instruction = Instruction(name=arg, rs=None, rt=None, rd=None, mem_addr=None, label=None)
                    procedures[curr_procedure].instructions.append(instruction)

                # Detect single register argument instructions
                elif arg in ["drf"]:
                    instruction = Instruction(name=arg, rs=line[1], rt=None, rd=None, mem_addr=None, label=None)
                    procedures[curr_procedure].instructions.append(instruction)

                # Detect unconditional jump instructions
                elif arg in ["jal", "goto"]:
                    instruction = Instruction(name=arg, rs=None, rt=None, rd=None, mem_addr=None, label=line[1])
                    procedures[curr_procedure].instructions.append(instruction)

                # default
                else:
                    print(
                        "Syntax Error in line {}: '{}' is not a valid instruction or is missing a ':' if it's a "
                        "procedure label".format(
                            num + 1,
                            arg))
                    sys.exit(2)

    print("Done!")
    return procedures


def hasEnoughMemory(addr, size=256):
    """
    Checks if too much memory is used (which would overwrite ISRs)

    :param addr: ROM address
    :param size: Size of ROM (in bytes)
    :return: true if within memory bounds else throws error
    """

    if addr < size - 2:
        return True
    else:
        raise Exception("Out of ROM Memory!")


def decodeInstruction(instruction):
    """
    This function decodes the input instruction into hex machine code

    :param instruction: Instruction to be decoded
    :return: hex machine code
    """
    name = instruction.name
    if name == "lw":
        return "%02x" % (ord(instruction.rs) - 65)
    elif name == "sw":
        return "%02x" % (ord(instruction.rs) - 63)
    elif name == "add":
        return '0' + "%01x" % (ord(instruction.rd) - 61)
    elif name == "sub":
        return '1' + "%01x" % (ord(instruction.rd) - 61)
    elif name == "mul":
        return '2' + "%01x" % (ord(instruction.rd) - 61)
    elif name == "sll":
        return '3' + "%01x" % (ord(instruction.rd) - 61)
    elif name == "srl":
        return '4' + "%01x" % (ord(instruction.rd) - 61)
    elif name == "inc":
        return "%01x" % (ord(instruction.rd) - 60) + "%01x" % (ord(instruction.rd) - 61)
    elif name == "dec":
        return "%01x" % (ord(instruction.rd) - 61) + "%01x" % (ord(instruction.rd) - 61)
    elif name == "beq":
        return "96"
    elif name == "bgt":
        return "A6"
    elif name == "blt":
        return "B6"
    elif name == "goto":
        return "07"
    elif name == "idle":
        return "08"
    elif name == "jal":
        return "09"
    elif name == "ra":
        return "0A"
    elif name == "drf":
        return '0' + str(chr(ord(instruction.rs) + 1))
    else:
        raise Exception("Instruction not implemented yet!")


def map(procedures, rom_size=256, debug=False):
    """
    This function maps the stored procedures into ROM memory

    :param rom_size: Size of ROM
    :return: a list representing the ROM
    """
    print("Mapping assembly code to ROM...")

    if "main" not in procedures or "Mouse_Interrupt" not in procedures or "Timer_Interrupt" not in procedures:
        print("File is missing the necessary procedures!")
        sys.exit(2)

    # Program Counter
    pc = 0
    # ROM
    rom = ["00"] * rom_size

    # allocate memory for main procedure
    procedure_size = len(procedures["main"])
    hasEnoughMemory(pc + procedure_size, rom_size)
    # map current PC to the main procedure
    procedures["main"].addr_in_ROM = pc
    pc += procedure_size

    # allocate memory for interrupt routine for mouse
    procedure_size = len(procedures["Mouse_Interrupt"])
    hasEnoughMemory(pc + procedure_size, rom_size)
    # map address of Mouse Interrupt routine to service handler location
    rom[0xFF] = "%02x" % pc
    # map current PC to the Mouse Interrupt Routine
    procedures["Mouse_Interrupt"].addr_in_ROM = pc
    pc += procedure_size

    # allocate memory for interrupt routine for timer
    procedure_size = len(procedures["Timer_Interrupt"])
    hasEnoughMemory(pc + procedure_size, rom_size)
    # map address of Timer Interrupt routine to service handler location
    rom[0xFE] = "%02x" % pc
    # map current PC to the Timer Interrupt Routine
    procedures["Timer_Interrupt"].addr_in_ROM = pc
    pc += procedure_size

    # Loop through remaining procedures and map them to ROM memory
    for procedure in procedures.values():
        if procedure.procedure_name not in ["main", "Mouse_Interrupt", "Timer_Interrupt"]:
            procedure_size = len(procedure)

            if debug:
                print("Procedure: {} , Size of Procedure: {}".format(procedure.procedure_name, procedure_size))

            hasEnoughMemory(pc + procedure_size, rom_size)

            # map address to start of procedure
            procedure.addr_in_ROM = pc
            pc += procedure_size

    # Loop through instructions in each procedure and map them to addresses in the ROM
    for procedure in procedures.values():
        offset = 0

        if debug:
            print("Procedure: {} , Address: {}".format(procedure.procedure_name, procedure.addr_in_ROM))

        # Loop through instructions
        for instruction in procedure.instructions:
            if debug:
                print("{} , Address: {}".format(instruction.name, procedure.addr_in_ROM + offset))

            # Decode and map load/store instructions
            if instruction.name in ["lw", "sw"]:
                hex_code = decodeInstruction(instruction)
                rom[procedure.addr_in_ROM + offset] = hex_code
                rom[procedure.addr_in_ROM + offset + 1] = instruction.mem_addr
                offset += 2

            # Decode and map branch and other 2 byte instructions
            elif instruction.name in ["beq", "bgt", "blt", "goto", "jal"]:
                if instruction.label not in procedures.keys():
                    print("Syntax Error in Label(s)!")
                    sys.exit(2)
                hex_code = decodeInstruction(instruction)
                rom[procedure.addr_in_ROM + offset] = hex_code
                rom[procedure.addr_in_ROM + offset + 1] = "%02x" % procedures[instruction.label].addr_in_ROM
                offset += 2

            # Decode and map single byte instructions
            else:
                hex_code = decodeInstruction(instruction)
                rom[procedure.addr_in_ROM + offset] = hex_code
                offset += 1
    print("Done!")
    return rom


def export(output_file, rom):
    with open(output_file, 'w') as f:
        print("Creating ROM file...")

        for addr in rom:
            f.write(str(addr) + '\n')

        print("Done!")


if __name__ == "__main__":
    input_file, output_file, debug, rom_size = parse_stdin()
    procedures = parse_assembly(input_file, debug=debug)
    rom = map(procedures, rom_size=rom_size, debug=debug)
    export(output_file, rom)
