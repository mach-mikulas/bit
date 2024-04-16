import random
import secrets
from tqdm import tqdm


def binary_or(bin_str1, bin_str2):
    result = ""

    for i in range(0, len(bin_str1)):
        # Perform OR operation between corresponding bits
        if bin_str1[i] == "1" and bin_str2[i] == "1":
            result += "0"
            continue
        elif bin_str1[i] == "1" and bin_str2[i] == "0":
            result += "1"
            continue
        elif bin_str1[i] == "0" and bin_str2[i] == "1":
            result += "1"
            continue
        elif bin_str1[i] == "0" and bin_str2[i] == "0":
            result += "0"
            continue

    return result


def split_binary_string(binary_str):
    # Ensure the length of the binary string is divisible by 6
    # if len(binary_str) % 6 != 0:
    #    raise ValueError("Binary string length must be divisible by 6")

    # Split the binary string into groups of six bits
    substrings = [binary_str[i:i + 6] for i in range(0, len(binary_str), 6)]

    # print("Splited binary in groups of 6: ", substrings)

    return substrings


def xor_binary_strings(str1, str2):

    result = ''.join(str(int(bit1) ^ int(bit2)) for bit1, bit2 in zip(str1, str2))
    # print("XOR K+E(R) in binary: ", result)

    return result


class Des:
    ROUNDS = 16
    BYTE_BLOCK_SIZE = 8
    key_plus = ""
    key_plus_c = []
    key_plus_d = []
    key_plus_k = [""]
    key_plus_k_reversed = []
    ip_l = []
    ip_r = []
    PC_1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    NUM_OF_SHIFTS = [0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    PC_2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    E_BIT = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    S_1 = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ]

    S_2 = [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ]

    S_3 = [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ]

    S_4 = [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ]

    S_5 = [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ]

    S_6 = [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ]

    S_7 = [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ]

    S_8 = [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]

    S_BOXES = ["", S_1, S_2, S_3, S_4, S_5, S_6, S_7, S_8]

    P = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]

    IP_1 = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]


    ## TODO Here you can specify the pboxes, sboxes and other necessary tables

    def __init__(self, encryption: bool = True):
        self.encryption = encryption
        self.key_plus = ""
        self.key_plus_c = []
        self.key_plus_d = []
        self.key_plus_k = [""]
        self.key_plus_k_reversed = []
        self.ip_l = []
        self.ip_r = []
        self.result = bytes()

    def create_key(self):

        random_bytes = secrets.token_bytes(8)
        return random_bytes.hex()

    def get_key_plus(self, key):

        key_plus = ""

        # print("Key in hex: ", key)

        binary_key = bin(key)
        binary_key = binary_key[2:]
        binary_key = binary_key.zfill(64)

        # print("Key in binary: ", binary_key)

        for index_pc_1 in self.PC_1:
            key_plus += binary_key[index_pc_1-1]

        # print("Key+ in binary: ", key_plus)

        self.key_plus = key_plus

        middle_index = len(key_plus) // 2
        self.key_plus_c.append(key_plus[:middle_index])
        self.key_plus_d.append(key_plus[middle_index:])

        # print("Key+ c0 in binary: ", self.key_plus_c[0])
        # print("Key+ d0 in binary: ", self.key_plus_d[0])

    def left_rotation_key_all(self):

        for i in range(1, 17):
            self.left_rotation_key(i)

    def left_rotation_key(self, index):

        key_plus_c_rotated = self.key_plus_c[index - 1]
        key_plus_d_rotated = self.key_plus_d[index - 1]

        for _ in range(0, self.NUM_OF_SHIFTS[index]):
            # print("Rotation index: ", index, " Num_of_shifts: ", self.NUM_OF_SHIFTS[index])
            key_plus_c_rotated = key_plus_c_rotated[1:] + key_plus_c_rotated[0]
            key_plus_d_rotated = key_plus_d_rotated[1:] + key_plus_d_rotated[0]

        self.key_plus_c.append(key_plus_c_rotated)
        self.key_plus_d.append(key_plus_d_rotated)

        # print("Key+ c", index, " in binary: ", self.key_plus_c[index])
        # print("Key+ d", index, " in binary: ", self.key_plus_d[index])

    def form_k_keys(self):

        for index in range(1, 17):
            key_plus_k = ""
            key_plus_cd = self.key_plus_c[index] + self.key_plus_d[index]
            # print("Key+ cd", index, " in binary: ", key_plus_cd)

            for index_pc_2 in self.PC_2:
                # print("LEN: ", len(key_plus_cd), "INDEX: ", index_pc_2)
                key_plus_k += key_plus_cd[index_pc_2 - 1]

            self.key_plus_k.append(key_plus_k)
            # print("Key+ k", index, " in binary: ", self.key_plus_k[index])

    def m_to_ip(self, data_block):

        data_block_binary = bin(data_block)
        data_block_binary = data_block_binary[2:]
        data_block_binary = data_block_binary.zfill(64)
        # print("Data block in binary: ", data_block_binary)
        ip_block = ""

        for index_ip in self.IP:
            ip_block += data_block_binary[index_ip-1]

        # print("IP block in binary: ", ip_block)

        middle_index = len(ip_block) // 2
        self.ip_l.append(ip_block[:middle_index])
        self.ip_r.append(ip_block[middle_index:])

        # print("IP_L0 in binary: ", self.ip_l[0])
        # print("IP_R0 in binary: ", self.ip_r[0])

    def r_expand(self, index):
        r_expand_n = ""
        for index_e_bit in self.E_BIT:
            r_expand_n += self.ip_r[index-1][index_e_bit-1]

        # print("Expanded R", index-1, " in binary: ", r_expand_n)

        return r_expand_n

    def function_f(self, index):
        r_expand_n = self.r_expand(index)
        xor_k_r = xor_binary_strings(self.key_plus_k[index], r_expand_n)
        groups_of_6_bits = split_binary_string(xor_k_r)

        s_box_result = ""

        for i in range(0, 8):

            row_adr = groups_of_6_bits[i][0] + groups_of_6_bits[i][-1]
            col_adr = groups_of_6_bits[i][1:-1]

            string = bin(self.S_BOXES[i + 1][int(row_adr, 2)][int(col_adr, 2)])
            string = string[2:]
            string = string.zfill(4)
            s_box_result += string

        # print("S_box output", index, " result in binary: ", s_box_result)

        f_result = ""

        for index_p in self.P:
            f_result += s_box_result[index_p-1]

        # print("F result at index ", index, " in binary: ", f_result)

        return f_result

    def perform_des(self, input_bytes, key):

        self.result = bytes()

        # print("Len input:", len(input_bytes))

        if self.encryption:
            num_of_bytes = len(input_bytes)

            if num_of_bytes % 8 == 0:
                num_of_padding = 8
            else:
                num_of_padding = 8 - num_of_bytes % 8

            # print("Number of bytes: ", num_of_bytes)
            # print("Number of padding bytes: ", num_of_padding)

            zero_byte = b'\x00'

            # print("INPUT befor = ", input_bytes)

            input_bytes += zero_byte * (num_of_padding - 1)
            input_bytes += bytes([num_of_padding])

            # print("Len input after padding:", len(input_bytes))

            # print("INPUT after = ", input_bytes)

        # print("INPUT = ", input_bytes)

        #if not isinstance(input_bytes, int):
        #    input_bytes = int.from_bytes(input_bytes, byteorder='big')

        #print("INPUT = ", input_bytes)

        self.get_key_plus(key)
        self.left_rotation_key_all()
        self.form_k_keys()

        bar_msg = "Encrypting 64bit blocks"

        if not self.encryption:
            self.key_plus_k.append("")
            self.key_plus_k = self.key_plus_k[1:]
            self.key_plus_k.reverse()
            bar_msg = "Decrypting 64bit blocks"

        for byte_index in tqdm(range(0, len(input_bytes), 8), desc=bar_msg):
            byte_block = input_bytes[byte_index:byte_index + 8]
            byte_block = int.from_bytes(byte_block, byteorder='big')

            # print(byte_block)

            self.m_to_ip(byte_block)

            for i in range(1, 17):
                self.ip_l.append(self.ip_r[i - 1])
                self.ip_r.append(binary_or(self.ip_l[i - 1], self.function_f(i)))

            # print("L16 in binary: ", self.ip_l[16])
            # print("R16 in binary: ", self.ip_r[16])

            r16_l16 = self.ip_r[16] + self.ip_l[16]

            result = ""

            for index_ip_1 in self.IP_1:
                result += r16_l16[index_ip_1 - 1]


            # print(result)
            self.result += bytes(int(result[x:x + 8], 2) for x in range(0, len(result), 8))
            self.ip_l = []
            self.ip_r = []

            # if self.encryption:
            #     print("Encode result in binary: ", result)
            #     print("Encode result in hex: ", hex(int(result, 2)))
            #     print("Encode result in int: ", int(result, 2))
            # else:
            #     print("Decoded result in binary: ", result)
            #     print("Decoded result in hex: ", hex(int(result, 2)))
            #     print("Decoded result in int: ", int(result, 2))

        if not self.encryption:
            # print("Len output:", len(self.result))
            # print("Print result with padding: ", self.result)
            # print("Last byte: ", self.result[-1])

            # last_byte = self.result[:-1]
            # print(last_byte)
            # num_of_padding_dec = int.from_bytes(last_byte, byteorder='big')
            num_of_padding_dec = self.result[-1]
            # print("Num of padding in dec: ", num_of_padding_dec)

            self.result = self.result[:-num_of_padding_dec]

        # return int(result, 2)

        #print("Len:", len(self.result))
        #print(result)
        return self.result
    ### TODO recommend to create small functions that tackles individual operations
