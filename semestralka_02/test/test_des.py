import subprocess
import unittest
import os
import math
import re


DATA_SOURCE = os.path.join("..", "validation")
OUTPUT_DIR = os.path.join("..", "out")
DECODED_DIR = os.path.join("..", "decoded")
KEY_FILEPATH = os.path.join("..", "key.txt")

class DESTester(unittest.TestCase):

    def test_key_format(self):
        with open(KEY_FILEPATH, mode="r") as fr:
            hexa_string = fr.read()
        if "0x" in hexa_string:
            print("Ox should not be at beginning of hexa string")
            return False

        pattern = re.compile('[123456789abcdef]')
        if not re.search(pattern, hexa_string):
            print("Key must contain only characters: 123456789abcedf")
            return False

        if len(hexa_string) != 16:
            print("Key must be 8 bytes long!")
            return False
        return True

    def test_padding(self):
        """
        This test method check if all files in output dir have padding --> number of bytes % 8 == 0
        :return:
        """
        for file in os.listdir(OUTPUT_DIR):
            filepath = os.path.join(OUTPUT_DIR, file)
            with open(filepath, mode="rb") as fr:
                bytes_count = len(fr.read())
                if bytes_count % 8 != 0:
                    print(f"File {filepath} probably has no padding.")
                    return False
        return True

    def test_decoded_results(self):
        """
        This test compares all files in DATA_SOURCE contra all files in DECODED_DIR
        """
        for decoded_file in sorted(os.listdir(DECODED_DIR)):
            decoded_filename = os.path.join(DECODED_DIR, decoded_file)
            for validation_file in sorted(os.listdir(DATA_SOURCE)):
                validation_filename = os.path.join(DATA_SOURCE, validation_file)
                if decoded_file == validation_file:
                    # check if files are identical
                    with open(decoded_filename, "rb") as fr:
                        decoded_bytes = fr.read()

                    with open(validation_filename, "rb") as fr:
                        validation_bytes = fr.read()
                    print(f"Comparing {validation_filename} and {decoded_filename}")
                    assert decoded_bytes == validation_bytes
                    print("OK")
                    break


