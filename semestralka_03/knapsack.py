import random
from collections import deque
from tqdm import tqdm

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def generate_random_prime(start, end):
    while True:
        random_num = random.randint(start, end)
        if is_prime(random_num):
            return random_num


def get_bit(num, bit_pos):
    # Create a mask with only the bit at bit_pos set to 1
    mask = 1 << bit_pos
    # Perform bitwise AND with the mask to extract the bit
    bit_value = (num & mask) >> bit_pos
    return bit_value


class Knapsack:

    BLOCK_SIZE = 250

    def __init__(self, encryption: bool = True):
        self.encryption = encryption
        self.private_key_sum = 0
        self.private_key = []
        self.public_key = []
        self.q = 0
        self.p = 0

    def create_private_key(self):

        while True:
            first_num = random.getrandbits(100)

            if first_num.bit_length() == 100:
                self.private_key.append(first_num)
                self.private_key_sum += first_num
                break

        while len(self.private_key) < self.BLOCK_SIZE:
            random_num = random.randint(1, 1000)
            last_num = self.private_key_sum + random_num
            self.private_key_sum += last_num
            self.private_key.append(last_num)

        return self.private_key

    def generate_q(self):
        random_num = random.randint(1, 50)
        self.q = self.private_key_sum + random_num

        print("Generated q: ", self.q)

        return self.q

    def generate_p(self):
        self.p = generate_random_prime(1, 1000)

        print("Generated p: ", self.p)

        return self.p

    def generate_public_key(self):

        for private_num in self.private_key:
            self.public_key.append((private_num * self.p) % self.q)

        return self.public_key

    def perform_knapsack(self, input_int: int, public_key: list[int]):
        blocks = []
        result = []
        input_bit_length = input_int.bit_length()

        print("")

        for i in range(0, input_bit_length, self.BLOCK_SIZE):
            start_index = input_bit_length - i - self.BLOCK_SIZE
            block = (input_int >> max(start_index, 0)) & ((1 << min(self.BLOCK_SIZE, input_bit_length - i)) - 1)
            blocks.append(block)

        for block in tqdm(blocks, desc="Encryption"):

            encrypted_block = 0
            pub_key_index = 0 + self.BLOCK_SIZE - block.bit_length()

            for i in range(block.bit_length() - 1, -1, -1):
                bit_value = get_bit(block, i)
                # print(len(public_key))
                encrypted_block += bit_value * public_key[pub_key_index]
                # print("Index: ", pub_key_index, "Sum: ", encrypted_block)
                pub_key_index += 1
            result.append(encrypted_block)

        print()
        return result

    def knapsack_decrypt(self, input_int_list: list[int], private_key: list[int], p: int, q: int, padding: int):

        p_inverse = pow(p, -1, q)
        decrypted_file = []

        final_int = 0

        for block in tqdm(input_int_list, desc="Processing blocks"):
            weight = (block * p_inverse) % q
            decrypted_block = 0

            for private_weight in reversed(private_key):
                if weight >= private_weight:
                    decrypted_block |= 1 << (len(private_key) - 1 - private_key.index(private_weight))

                    weight -= private_weight

            final_int = (final_int << len(private_key)) | decrypted_block

        final_int >>= padding

        byte_obj = final_int.to_bytes((final_int.bit_length() + 7) // 8, byteorder='big')

        return byte_obj



