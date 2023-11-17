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

        binary.extend(s, self.additional_size)
        binary.extend(segment, self.additional_size)

        output_file = self.elf_file +"_modified"
        binary.write(output_file)

        return output_file