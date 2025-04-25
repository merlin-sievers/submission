import lief

class SectionExtender:
    def __init__(self, elf_file, additional_size):
        self.elf_file = elf_file
        self.additional_size = additional_size
    def extend_last_section_of_segment(self):
        # Load the ELF binary
        # config = lief.ELF.DYNSYM_COUNT_METHODS.SECTION
        lief.logging.enable()
        lief.logging.set_path("Testsuite/MAGMA/openssl/vuln/log.txt")
        lief.logging.set_level(lief.logging.LEVEL.DEBUG)
        # config.DYNSYM_COUNT.AUTO = True
        # config.DYNSYM_COUNT.HASH = True
        # config.DYNSYM_COUNT.RELOCATIONS = True
        binary = lief.parse(self.elf_file)

        binary_1 = lief.parse(self.elf_file)


        segment_type = lief.ELF.Segment.TYPE.LOAD # Type of segment to modify
        # # # Find the specified segment
        segment = next((seg for seg in binary.segments if seg.type == segment_type), None)
        segment_old = next((seg for seg in binary_1.segments if seg.type == segment_type), None)
        # # if segment is None or len(segment.sections) == 0:
        #     print(f"No segment of type {segment_type} found.")
        #     return
        # #
        # # # Get the last section of the segment

        for section in segment_old.sections:
            if section.name==".rel.plt":
                relplt_sec = section
            elif section.name == ".rel.dyn":
                reldyn_sec = section
        #

        index = list(binary.segments).index(segment)
        # # index = 1
        # #
        if binary.segments[index + 1].virtual_address - binary.segments[index].virtual_address < self.additional_size:
            print("Load segment and data segment are too close to each other. Cannot extend.")
            return
        # # Extend the section
        # # s.size += self.additional_size
        #
        #
        # # Extend the segment



        binary.extend(segment, self.additional_size)

        # # # TODO: Add check that segment can be extended
        # if binary.segments[index + 1].virtual_address - binary.segments[index].virtual_address < self.additional_size:
        #     print("Load segment and data segment are too close to each other. Cannot extend.")
        #     # return
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

        # TODO: Adapt to general case!
        # for seg in binary.segments:
        #     seg1 = seg
        #
        # seg1 = binary.segments[0]
        # seg2 = binary.segments[1]
        #
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


        # binary.segments[0].virtual_address = binary.segments[0].virtual_address + self.additional_size
        # binary.segments[0].physical_address = binary.segments[0].physical_address + self.additional_size


        # #
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

        i = 0

        # while i < len(binary.symbols):
        #     binary.symbols[i].value = binary_1.symbols[i].value
        #     i += 1

        i= 0
        while i < len(binary.relocations):
            binary.relocations[i].address = binary_1.relocations[i].address
            i += 1



        output_file = self.elf_file +"_modified"
        binary.write(output_file)


        # binarynew = lief.parse(output_file)
        # binarynew.write(output_file +"_2")



        return output_file


    def add_section(self):
        binary = lief.ELF.parse(self.elf_file)
        # binary1= lief.ELF.parse(self.elf_file)
        # Create a new section


        section = [s for s in binary.sections]
        if section == []:
            return None





        new_section = lief.ELF.Section(".patch")
        new_section.content = self.additional_size * [0x00]  # Fill with NOPs (64KB)
        new_section.flags = 6
        # Add the new section to the binary
        binary.add(new_section, True)
        #

        # for i in range(0, len(binary.segments)):
        #     if i <2:
        #         seg = binary.segments[i]
        #         seg1 = binary1.segments[i]
        #         binary.segments[i].virtual_address = binary1.segments[i].virtual_address
        #         binary.segments[i].physical_address = binary1.segments[i].physical_address
        #         binary.segments[i].alignment = binary1.segments[i].alignment
        #         # binary.segments[i].file_offset = binary1.segments[i].file_offset
        #         # binary.segments[i].virtual_size = binary1.segments[i].virtual_size
        #         # binary.segments[i].physical_size = binary1.segments[i].physical_size
        #         # binary.segments[i].content = binary1.segments[i].content
        #         for j in range(0, len(binary.segments[i].sections)):
        #     #         sec = binary.segments[i].sections[j]
        #     #         sec1 = binary1.segments[i].sections[j]
        #     #     #     binary.segments[i].sections[j].file_offset = binary1.segments[i].sections[j].file_offset
        #             binary.segments[i].sections[j].virtual_address = binary1.segments[i].sections[j].virtual_address
        #     #     #     binary.segments[i].sections[j].offset = binary1.segments[i].sections[j].offset
        #     #         binary.segments[i].sections[j].content = binary1.segments[i].sections[j].content
        #     elif i > 2:
        #     #     seg = binary.segments[i]
        #     #     seg1 = binary1.segments[i-1]
        #         binary.segments[i].virtual_address = binary1.segments[i-1].virtual_address
        #         binary.segments[i].physical_address = binary1.segments[i-1].physical_address
        #         binary.segments[i].alignment = binary1.segments[i-1].alignment
        #     #     # binary.segments[i].file_offset = binary1.segments[i-1].file_offset
        #     #     # binary.segments[i].virtual_size = binary1.segments[i-1].virtual_size
        #     #     # binary.segments[i].physical_size = binary1.segments[i-1].physical_size
        #     #     binary.segments[i].content = binary1.segments[i-1].content
        #         for j in range(0, len(binary.segments[i].sections)):
        #     #     #     sec = binary.segments[i].sections[j]
        #     #     #     sec1 = binary1.segments[i-1].sections[j]
        #     #     #     # # binary.segments[i].sections[j].file_offset = binary1.segments[i-1].sections[j].file_offset
        #             binary.segments[i].sections[j].virtual_address = binary1.segments[i-1].sections[j].virtual_address
        #     #     #     # # binary.segments[i].sections[j].offset = binary1.segments[i-1].sections[j].offset
        #             binary.segments[i].sections[j].content = binary1.segments[i-1].sections[j].content
        #     #
        #     # else:
        #     #     pass
        # #
        # # binary.segments[2].virtual_address = binary.segments[2].virtual_address - 4096
        # # binary.segments[2].physical_address = binary.segments[2].physical_address - 4096
        # # binary.segments[2].alignment = 4096
        # # binary.segments[2].file_offset = binary.segments[2].file_offset - 4096
        # #
        # binary.segments[0].alignment = 4096
        # binary.segments[1].alignment = 4096
        # #
        # #
        # #
        #
        # i = 0
        # while i < len(binary.dynamic_entries):
        #     s = binary.dynamic_entries[i].value
        #     t = binary1.dynamic_entries[i].value
        #     entry = binary.dynamic_entries[i]
        #     entry1 = binary1.dynamic_entries[i]
        #     # if (entry.tag == lief.ELF.DynamicEntry.TAG.GNU_HASH):
        #     #     pass
        #     # else:
        #     #     binary.dynamic_entries[i].value = binary1.dynamic_entries[i].value
        #
        #     i += 1
        #
        # i = 0
        # while i < len(binary.dynamic_symbols):
        #     binary.dynamic_symbols[i].value = binary1.dynamic_symbols[i].value
        #     i += 1
        # #
        # i = 0
        # while i < len(binary.dynamic_relocations):
        #     binary.dynamic_relocations[i].address = binary1.dynamic_relocations[i].address
        #     i += 1
        # #
        # # i = 0
        # # #
        # while i < len(binary.symbols):
        #     binary.symbols[i].value = binary1.symbols[i].value
        #     i += 1
        # #
        # i = 0
        # while i < len(binary.relocations):
        #     binary.relocations[i].address = binary1.relocations[i].address
        #     i += 1


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
        # segment = next((seg for seg in binary.segments if seg.type == segment_type), None)
        segment = lief.ELF.Segment()
        segment.type = segment_type
        segment.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X | lief.ELF.Segment.FLAGS.W # Read & Write
        # segment.content = [0x90]
        # Fill with NOPs (4KB)
        # segment.virtual_address = next_va  # Set next available VA
        segment.physical_address = 0x88000  # Typically same as VA
        segment.alignment = 4096  # Page-aligned
        segment.file_offset = 540944
        segment.virtual_address = 0x88000# Set next available file offset
        segment.virtual_size = 0x1000  #4KB
        binary.add(segment, base=0x1000)

        list = [seg for seg in binary.segments]
        # for i in range(0, len(list)):
            # if i < 3:
            #     binary.segments[i].virtual_address = binary1.segments[i].virtual_address
            # else:
            #     binary.segments[i].virtual_address = binary1.segments[i-1].virtual_address

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

        binary_1 = lief.parse(self.elf_file)

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