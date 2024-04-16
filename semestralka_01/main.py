import os

STEGANOGRAPHY_IMG = "weber.bmp"
BMP_HEADER = 54
DATA_SOURCE = "validation/"
OUTPUT_DIR = "out/"
DECODED_DIR = "decoded/"


def bytes_to_bits(byte_string):

    return ' '.join(format(byte, '08b') for byte in byte_string)


def set_lsb(byte, new_lsb):

    modified_byte = bytes(byte & 0xFE | (new_lsb & 1))
    return modified_byte


def is_file_too_big(steganography_img_size, input_file_size):
    """
    Function determines if the input file is about to fit into STEGANOGRAPHY_IMG
    :param steganography_img_size: number of bytes of STEGANOGRAPHY_IMG
    :param input_file_size: number of bytes of an input file
    :return: True if input file fits, False otherwise
    """

    if steganography_img_size < input_file_size*8:

        return True

    else:

        return False


def hide(input_filepath, output_name):
    """
    This procedure performs steganography with the LSB method
    The part of a filepath is a filename and also a file extension
    :param input_filepath: the file which is about to hide into STEGANOGRAPHY IMG
    :param output_name: path to the encoded img with a hidden file
    """

    steganography_file_bytes = os.path.getsize(STEGANOGRAPHY_IMG) - BMP_HEADER
    input_file_bytes = os.path.getsize(input_filepath)

    if is_file_too_big(steganography_file_bytes, input_file_bytes):

        print(f"File {input_filepath} is too big for steganography!")
        return

    resulting_bytes = []

    with open(STEGANOGRAPHY_IMG, "rb") as steg_file:

        steg_file.seek(BMP_HEADER)

        #not working
        #for _ in range(54):
        #    steg_byte = steg_file.read(1)
        #    resulting_bytes.append(steg_byte)

        with open(input_filepath, "rb") as input_file:

            for _ in range(input_file_bytes):

                byte_input = input_file.read(1)

                for bit_index in range(0, 8):

                    bit = (byte_input[0] >> bit_index) & 1
                    steg_byte = steg_file.read(1)
                    new_steg_byte = bytes([steg_byte[0] & 0xFE | bit])
                    #new_steg_byte = set_lsb(steg_byte[0], bit)
                    resulting_bytes.append(new_steg_byte)

        steg_file.seek(0)
        steg_file_copy = steg_file.read()

    with open(output_name, "wb") as output_file:

        output_file.write(steg_file_copy)
        output_file.seek(BMP_HEADER)

        for byte in resulting_bytes:

            output_file.write(byte)


def decode(filepath):
    """
    This method decodes a hidden file from a filepath given as parameter and stores it into decoded folder.
    The part of a filepath is a filename and also a file extension
    :param merged_filepath:
    :return:
    """

    merged_file_bytes = None
    resulting_bytes = []
    # information about filename, extension and size are encoded in a filename
    basename_filepath = os.path.basename(filepath)
    print(basename_filepath)
    filename_parts = basename_filepath.split("___")
    filename = filename_parts[0]
    extension = filename_parts[1]
    size = int(filename_parts[2])

    bits = []
    buffer = 0

    with open(filepath, "rb") as file_decode:
        file_decode.seek(BMP_HEADER)
        bit_count = 0
        merged_file_bytes = file_decode.read()

        for byte_index in range(0, size*8):

            byte = merged_file_bytes[byte_index]
            bit = byte & 1
            bits.append(bit)

        bits.reverse()

        for bit in bits:

            buffer = (buffer << 1) | bit
            bit_count += 1

            if bit_count == 8:

                resulting_bytes.append(buffer.to_bytes(1, byteorder='little'))
                buffer = 0
                bit_count = 0

    filepath = os.path.join(DECODED_DIR, filename+"."+extension)

    resulting_bytes.reverse()

    with open(filepath, "wb") as decoded_file:

        for byte in resulting_bytes:

            decoded_file.write(byte)


if __name__ == '__main__':
    if not os.path.exists(DECODED_DIR):
        os.makedirs(DECODED_DIR)

    # 1. phase hiding (encoding) -- steganography
    if os.path.exists(DATA_SOURCE):
        files = sorted(os.listdir(DATA_SOURCE))
        for file in files:
            filepath = os.path.join(DATA_SOURCE, file)
            print(f"Hiding file {filepath} into {STEGANOGRAPHY_IMG}")
            filename, extension = file.split(".")
            size = os.stat(filepath).st_size
            output_filename = os.path.join(OUTPUT_DIR, filename+"___"+extension+"___"+str(size)+"___"+STEGANOGRAPHY_IMG)
            hide(filepath, output_name=output_filename)

    # 2. phase Decoding
    if os.path.exists(OUTPUT_DIR):
        files = sorted(os.listdir(OUTPUT_DIR))
        for file in files:
            filepath = os.path.join(OUTPUT_DIR, file)
            print(f"Decoding a hidden file from {filepath}")
            decode(filepath)