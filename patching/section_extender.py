import lief

class SectionExtender:
    def __init__(self, elf_file, additional_size):
        self.elf_file = elf_file
        self.additional_size = additional_size
    def extend_last_section_of_segment(self):
        # Load the ELF binary
        binary = lief.parse(self.elf_file)
        binary_1 = lief.parse(self.elf_file)
        segment_type = lief.ELF.SEGMENT_TYPES.LOAD  # Type of segment to modify
        # Find the specified segment
        segment = next((seg for seg in binary.segments if seg.type == segment_type), None)
        segment_old = next((seg for seg in binary_1.segments if seg.type == segment_type), None)
        if segment is None or len(segment.sections) == 0:
            print(f"No segment of type {segment_type} found.")
            return

        # Get the last section of the segment
        for section in segment_old.sections:
            if section.name==".rel.plt":
                relplt_sec = section
            elif section.name == ".rel.dyn":
                reldyn_sec = section

        if binary.segments[1].virtual_address - binary.segments[0].virtual_address < self.additional_size:
            print("Load segment and data segment are too close to each other. Cannot extend.")
            return
        # Extend the section
        # s.size += self.additional_size


        # # Extend the segment



        binary.extend(segment, self.additional_size)

        # # TODO: Add check that segment can be extended
        if binary.segments[1].virtual_address - binary.segments[0].virtual_address < self.additional_size:
            print("Load segment and data segment are too close to each other. Cannot extend.")
            return
        i = 0
        while  i < len(binary.segments[0].sections):
            binary.segments[0].sections[i].content = binary_1.segments[0].sections[i].content
            i += 1

        i = 0
        while i < len(binary.segments[1].sections):
            binary.segments[1].sections[i].content = binary_1.segments[1].sections[i].content
            i += 1

        while i < len(binary.segments[2].sections):
            binary.segments[2].sections[i].content = binary_1.segments[2].sections[i].content
            i += 1



        # TODO: Adapt to general case!
        for seg in binary.segments:
            seg1 = seg

        segment = next((seg for seg in binary.segments if seg.type ==lief.ELF.SEGMENT_TYPES.GNU_RELRO), None)
        segment.virtual_address = segment.virtual_address - self.additional_size
        segment.physical_address = segment.physical_address - self.additional_size

        binary.segments[1].virtual_address = binary.segments[1].virtual_address - self.additional_size
        binary.segments[1].alignment = binary.segments[1].alignment = 4096
        binary.segments[1].physical_address = binary.segments[1].physical_address - self.additional_size
        for s in binary.segments[1].sections:
            s.virtual_address = s.virtual_address - self.additional_size

        binary.segments[2].virtual_address = binary.segments[2].virtual_address - self.additional_size
        binary.segments[2].physical_address = binary.segments[2].physical_address - self.additional_size
        # for s in binary.segments[2].sections:
        #     s.virtual_address = s.virtual_address - self.additional_size

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
        while i < len(binary.static_symbols):
            binary.static_symbols[i].value = binary_1.static_symbols[i].value
            i += 1

        i= 0
        while i < len(binary.relocations):
            binary.relocations[i].address = binary_1.relocations[i].address
            i += 1



        output_file = self.elf_file +"_modified"
        binary.write(output_file)

        return output_file


    def add_section(self):
        binary = lief.parse(self.elf_file)
        segment_type = lief.ELF.SEGMENT_TYPES.LOAD  # Type of segment to modify

        highest_va = 0
        last_loadable_section = None
        for segment in binary.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                if segment.virtual_address + segment.virtual_size > highest_va:
                    highest_va = segment.virtual_address + segment.virtual_size
                    # Get the last section within this loadable segment
                    for section in binary.sections:
                        if segment.virtual_address <= section.virtual_address < segment.virtual_address + segment.virtual_size:
                            last_loadable_section = section



        # Find the specified segment
        segment = next((seg for seg in binary.segments if seg.type == segment_type), None)
        if segment is None or len(segment.sections) == 0:
            print(f"No segment of type {segment_type} found.")
            return


        # Get the last section of the segment
        for section in segment.sections:
            s = section


        # Create a new section
        new_section = lief.ELF.Section(".my_section")
        new_section.content = section.content
        new_section.flags = section.flags

        # Add the new section to the binary
        binary.add(new_section, True)


        output_file = self.elf_file +"_modified"
        # Save the modified binary to disk
        binary.write(output_file)

        return output_file

