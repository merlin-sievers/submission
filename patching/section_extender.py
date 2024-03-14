import lief

class SectionExtender:
    def __init__(self, elf_file, additional_size):
        self.elf_file = elf_file
        self.additional_size = additional_size
    def extend_last_section_of_segment(self):
        # Load the ELF binary
        binary = lief.parse(self.elf_file)
        segment_type = lief.ELF.SEGMENT_TYPES.LOAD  # Type of segment to modify
        # Find the specified segment
        segment = next((seg for seg in binary.segments if seg.type == segment_type), None)
        if segment is None or len(segment.sections) == 0:
            print(f"No segment of type {segment_type} found.")
            return

        # Get the last section of the segment
        for section in segment.sections:
            s = section

        # Extend the section
        s.size += self.additional_size

        binary.extend(segment, self.additional_size)

        # TODO: Add check that segment can be extended



        # TODO: Adapt to general case!

        binary.segments[1].virtual_address = binary.segments[1].virtual_address - self.additional_size

        binary.segments[1].sections[0].virtual_address = binary.segments[1].virtual_address - self.additional_size


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

