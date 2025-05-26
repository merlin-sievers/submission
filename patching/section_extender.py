import lief

class SectionExtender:
    """
    A class for extending or adding sections to ELF binary files.

    This class provides methods to:
    - Extend the last section of a segment
    - Add a new section to a binary
    - Add a new segment to a binary
    - Extend a monolithic firmware
    - Add a section with specific program header and dynamic section information

    Attributes:
        elf_file (str): Path to the ELF binary file to modify
        additional_size (int): Size in bytes to extend the section or segment by
    """
    def __init__(self, elf_file, additional_size):
        """
        Initialize the SectionExtender with an ELF file and additional size.

        Args:
            elf_file (str): Path to the ELF binary file to modify
            additional_size (int): Size in bytes to extend the section or segment by
        """
        self.elf_file = elf_file
        self.additional_size = additional_size

    def extend_last_section_of_segment(self):
        lief.logging.enable()
        lief.logging.set_path("Testsuite/MAGMA/openssl/vuln/log.txt")
        lief.logging.set_level(lief.logging.LEVEL.DEBUG)

        binary = lief.parse(self.elf_file)

        binary_1 = lief.parse(self.elf_file)


        segment_type = lief.ELF.Segment.TYPE.LOAD # Type of segment to modify
        # # # Find the specified segment
        segment = next((seg for seg in binary.segments if seg.type == segment_type), None)
        segment_old = next((seg for seg in binary_1.segments if seg.type == segment_type), None)

        for section in segment_old.sections:
            if section.name==".rel.plt":
                relplt_sec = section
            elif section.name == ".rel.dyn":
                reldyn_sec = section


        index = list(binary.segments).index(segment)


        if binary.segments[index + 1].virtual_address - binary.segments[index].virtual_address < self.additional_size:
            print("Load segment and data segment are too close to each other. Cannot extend.")
            return


        binary.extend(segment, self.additional_size)

        i = 0
        while  i < len(binary.segments[index].sections):
            binary.segments[index].sections[i].content = binary_1.segments[index].sections[i].content
            sec = binary.segments[index].sections[i]
            content = binary.segments[index].sections[i].content
            i += 1

        i = 0
        while i < len(binary.segments[index+1].sections):
            binary.segments[index+1].sections[i].content = binary_1.segments[index+1].sections[i].content
            i += 1

        while i < len(binary.segments[index+2].sections):
            binary.segments[index+2].sections[i].content = binary_1.segments[index+2].sections[i].content
            i += 1

        i = 0
        while i < len(binary.segments[0].sections):
            binary.segments[0].sections[i].content = binary_1.segments[0].sections[i].content
            i += 1

        segment = next((seg for seg in binary.segments if seg.type ==lief.ELF.Segment.TYPE.GNU_RELRO), None)
        if segment is not None:
            segment.virtual_address = segment.virtual_address - self.additional_size
            segment.physical_address = segment.physical_address - self.additional_size

        binary.segments[index + 1].virtual_address = binary.segments[index + 1].virtual_address - self.additional_size
        binary.segments[index + 1].alignment =  binary_1.segments[index + 1].alignment
        binary.segments[index + 1].physical_address = binary.segments[index + 1].physical_address - self.additional_size
        for s in binary.segments[index + 1].sections:
            s.virtual_address = s.virtual_address - self.additional_size

        binary.segments[index + 2].virtual_address = binary.segments[index + 2].virtual_address - self.additional_size
        binary.segments[index + 2].physical_address = binary.segments[index + 2].physical_address - self.additional_size
        for s in binary.segments[2].sections:
            s.virtual_address = s.virtual_address - self.additional_size

        i= 0
        while i < len(binary.dynamic_entries):

            binary.dynamic_entries[i].value = binary_1.dynamic_entries[i].value
            i += 1

        i = 0
        while i < len(binary.dynamic_symbols):
            binary.dynamic_symbols[i].value = binary_1.dynamic_symbols[i].value
            i += 1

        i = 0
        while i < len(binary.dynamic_relocations):
            binary.dynamic_relocations[i].address = binary_1.dynamic_relocations[i].address
            i += 1


        i= 0
        while i < len(binary.relocations):
            binary.relocations[i].address = binary_1.relocations[i].address
            i += 1



        output_file = self.elf_file +"_modified"
        binary.write(output_file)

        return output_file


    def add_section(self) -> str | None:
        binary = lief.ELF.parse(self.elf_file)

        section = [s for s in binary.sections]
        if section == []:
            return None

        new_section = lief.ELF.Section(".patch")
        new_section.content = self.additional_size * [0x00]  # Fill with NOPs (64KB)
        new_section.flags = 6
        # Add the new section to the binary
        binary.add(new_section, True)

        output_file = self.elf_file +"_modified"
        # Save the modified binary to disk
        binary.write(output_file)

        return output_file

    def add_new_segment(self):
        # Parse binary
        binary = lief.parse(self.elf_file)
        binary1 = lief.parse(self.elf_file)
        # Find the last segment's virtual address + size
        max_va = max(seg.virtual_address + seg.virtual_size for seg in binary.segments)

        # Align to the next page (0x1000-aligned)
        next_va = (max_va + 0x1000) & ~0xFFF

        # Find the last segment's file offset + size
        max_offset = max(seg.file_offset + seg.virtual_size for seg in binary.segments)

        max_offset = binary.eof_offset


        maxa = max(seg.file_offset for seg in binary.segments)
        # Align to the next file offset (optional, but recommended)
        next_offset = (max_offset + 0x1000) & ~0xFFF

        segment_type = (lief.ELF.Segment.TYPE.LOAD)  # Loadable segment
        # Create a new segment

        segment = lief.ELF.Segment()
        segment.type = segment_type
        segment.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X | lief.ELF.Segment.FLAGS.W # Read & Write

        segment.physical_address = 0x88000  # Typically same as VA
        segment.alignment = 4096  # Page-aligned
        segment.file_offset = 540944
        segment.virtual_address = 0x88000# Set next available file offset
        segment.virtual_size = 0x1000  #4KB
        binary.add(segment, base=0x1000)


        binary.segments[2].virtual_address = 0x88000
        binary.segments[2].flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X  # Read & Write

        binary.segments[2].physical_size = 65536
        binary.segments[2].content = binary.segments[1].content

        # Fill with NOPs (4KB)
        binary.segments[2].virtual_address = next_va  # Set next available VA
        binary.segments[2].physical_address = next_va  # Typically same as VA
        binary.segments[2].alignment = 4096  # Page-aligned
        binary.segments[2].file_offset = 0x88000
        binary.segments[2].virtual_address = next_va  # Set next available file offset
        binary.segments[2].virtual_size = self.additional_size
        binary.write("modified_binary.elf")
        return "modified_binary.elf"

    def extend_monolithic_firmware(self):
        binary = lief.parse(self.elf_file)

        segment_type = lief.ELF.Segment.TYPE.LOAD  # Type of segment to modify

        max_segment = None
        max_offset = 0

        for seg in binary.segments:
            if seg.type == segment_type:  # Ensure it matches the desired segment type
                if seg.file_offset > max_offset:
                    max_offset = seg.file_offset
                    max_segment = seg

        binary.extend(max_segment, self.additional_size)
        output_file = self.elf_file + "_modified"
        binary.write(output_file)
        return output_file

    def add_section_with_program_header(self) -> str:

        binary = lief.parse(self.elf_file)
        binary1 = lief.parse(self.elf_file)

        # Create a new section
        new_section = lief.ELF.Section("patch")
        new_section.content = self.additional_size * [0x00]  # Fill with zeros
        new_section.flags = lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR  # Executable section


        # Add the new segment
        binary.add(new_section)
        header1 = binary1.header
        header = binary.header
        # Write the modified binary to disk
        header.section_header_offset = 0
        header.numberof_sections = 0
        output_file = self.elf_file + ("_modified")

        binary.write(output_file)
        # elf.write(output_file)

        return output_file
