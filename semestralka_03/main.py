import os
import sys
from knapsack import Knapsack

DATA_SOURCE = "validation"
OUTPUT_DIR = "out"
DECODED_DIR = "decoded"
PUBLIC_KEY_FILE = "public_key.txt"
PRIVATE_KEY_FILE = "private_key.txt"
P_FILE = "p.txt"
Q_FILE = "q.txt"
BLOCK_SIZE = 250


def prepare_for_knap(knap_object):
    private_key = knap_object.create_private_key()

    with open(os.path.join(os.path.dirname(__file__), PRIVATE_KEY_FILE), "w") as file_private:

        for i in range(len(private_key)):
            file_private.write(str(private_key[i]))

            if i != len(private_key) - 1:
                file_private.write(",")

    q = knap_object.generate_q()

    with open(os.path.join(os.path.dirname(__file__), Q_FILE), "w") as file_q:
        file_q.write(str(q))

    p = knap_object.generate_p()

    with open(os.path.join(os.path.dirname(__file__), P_FILE), "w") as file_q:
        file_q.write(str(p))

    public_key = knap.generate_public_key()

    with open(os.path.join(os.path.dirname(__file__), PUBLIC_KEY_FILE), "w") as file_public:

        for i in range(len(public_key)):
            file_public.write(str(public_key[i]))

            if i != len(public_key) - 1:
                file_public.write(",")


if __name__ == '__main__':

    DEBUG = False


    if DEBUG == True:
        test_input = 151342
        private_key = [1,2,4,10,20,40]
        public_key = [31,62,14,90,70,30]
        p = 31
        q = 110

        debug_knap = Knapsack(encryption=True)

        out = debug_knap.perform_knapsack(test_input,public_key=public_key)

        debug_knap_dec = Knapsack(encryption=False)

        out_dec = debug_knap_dec.knapsack_decrypt(out, private_key=private_key,p=p,q=q,padding=0)

    else:

        if len(sys.argv) != 2:
            print("Exactly one argument is expected (either -e or -d)")
            exit(1)
        else:
            mode = sys.argv[1]
            data_folder = None
            if mode == "-e":
                print("Encryption mode")
                knap = Knapsack(encryption=True)
                data_folder = DATA_SOURCE
                output_folder = OUTPUT_DIR

                prepare_for_knap(knap)

                print("------------------------")

            elif mode == "-d":
                print("Decryption mode")
                knap = Knapsack(encryption=False)
                data_folder = OUTPUT_DIR
                output_folder = DECODED_DIR
            else:
                print("Unknown mode... Choices are [-e, -d]")
                exit(1)

            if os.path.exists(data_folder):
                files = sorted(os.listdir(data_folder))
                print(f"{len(files)} files found in {data_folder}")
                print("------------------------")

                for file in files:

                    input_bytes = bytes()
                    input_list = []

                    if mode == "-e":
                        file_full_name = os.path.basename(file).split(".")

                        file_name = file_full_name[0]
                        file_extension = file_full_name[1]
                        print("File path: ", os.path.join(data_folder, file))

                        with open(os.path.join(data_folder, file), "rb") as file_to_read:
                            input_bytes = file_to_read.read()

                        input_int = int.from_bytes(input_bytes, byteorder='big')

                    elif mode == "-d":
                        file_full_name = os.path.basename(file).split(".")

                        split_index = file_full_name[0].rfind("_")
                        first_half = file_full_name[0][:split_index]
                        split_index_1 = first_half.find("_")
                        padding_from_filename = int(first_half[:split_index_1])
                        file_name = first_half[split_index_1 + 1:]

                        file_extension = file_full_name[0][split_index + 1:]

                        with open(os.path.join(data_folder, file), "r") as file_to_read:
                            print("File path: ", os.path.join(data_folder, file))
                            for line in file_to_read:
                                input_list.append(int(line))

                    # LOAD PUBLIC KEY
                    with open(os.path.join(os.path.dirname(__file__), PUBLIC_KEY_FILE), 'r') as file_public_key:
                        loaded_public_key = [int(num_str) for num_str in file_public_key.read().split(",")]
                    # LOAD PRIVATE KEY
                    with open(os.path.join(os.path.dirname(__file__), PRIVATE_KEY_FILE), 'r') as file_private_key:
                        loaded_private_key = [int(num_str) for num_str in file_private_key.read().split(",")]
                    # LOAD Q
                    with open(os.path.join(os.path.dirname(__file__), Q_FILE), 'r') as file_q_load:
                        loaded_q = int(file_q_load.read())
                    # LOAD P
                    with open(os.path.join(os.path.dirname(__file__), P_FILE), 'r') as file_p_load:
                        loaded_p = int(file_p_load.read())

                    padding = 0
                    output = []
                    output_decoded = bytes()

                    if mode == "-e":

                        bit_lenght = input_int.bit_length()

                        if not bit_lenght % BLOCK_SIZE == 0:

                            padding = BLOCK_SIZE - (bit_lenght % BLOCK_SIZE)
                            input_int = input_int << padding
                            output = knap.perform_knapsack(input_int, public_key=loaded_public_key)

                    elif mode == "-d":

                        output_decoded = knap.knapsack_decrypt(input_int_list=input_list, private_key=loaded_private_key,
                                                               q=loaded_q, p=loaded_p, padding=padding_from_filename)

                    print(f"Processing file {file}")

                    if knap.encryption:

                        new_file_name = str(padding) + "_" + file_name + "_" + file_extension + ".kna"

                        with open(os.path.join(os.path.dirname(__file__), output_folder, new_file_name), 'w') as file_out:
                            for i, block in enumerate(output):

                                file_out.write(str(block))

                                if i != len(output) - 1:
                                    file_out.write("\n")
                        print("File ", file_name + "." + file_extension, " encrypted")
                        pass
                    else:

                        new_file_name = file_name + "." + file_extension

                        with open(os.path.join(os.path.dirname(__file__), output_folder, new_file_name), 'wb') as file_out:
                            file_out.write(output_decoded)
                        print("File ", file_name + "." + file_extension, " decrypted")
                        pass

                    print("------------------------")