import sys
import os
from des import Des

DATA_SOURCE = "validation"
OUTPUT_DIR = "out"
DECODED_DIR = "decoded"
KEY_FILEPATH = "key.txt"

DEBUG = False

if __name__ == '__main__':


    # des = Des(encryption=True)
    # key = 0x133457799BBCDFF1
    # #debug_input = 81985529216486895
    # debug_input = 0x123456789ABCDEF
    # #des.get_key_plus(key)
    # #des.left_rotation_key_all()
    # #des.form_k_keys()
    #
    # # for _ in (0, 10000):
    # #des.m_to_ip(debug_input)
    # #des.function_f(1)
    #
    #
    # des.perform_des(debug_input, key)
    #
    # print("Done encryption")
    #
    # decdec = Des(encryption=False)
    # debug_dec_input = 0x85e813540f0ab405
    # decdec.perform_des(debug_dec_input, key)
    # print("Done decryption")

    if DEBUG:
        ## The purpose of this is to make sure that DES algorithm is correct
        # example is from https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

        print("WARNING: running in DEBUG mode!")
        debug_input: int = 81985529216486895
        debug_input_hex = "12345690abcdef"
        #debug_key: int = 1383827165325090801
        debug_key_hex = 0x133457799BBCDFF1

        # print(f"Input bytes hexa: {hex(debug_input)}")
        key = debug_key_hex
        des_encrypt = Des(encryption=True)
        debug_output_bytes = des_encrypt.perform_des(input_bytes=bytes.fromhex(debug_input_hex), key=key)

        ## decryption
        des_decrypt = Des(encryption=False)
        decoded_bytes = des_decrypt.perform_des(debug_output_bytes, key=key)


        # decoded must be equal to the debug_input if DES works correctly
        print(decoded_bytes)
        print(debug_input)
        assert decoded_bytes == int(debug_input_hex, 16)
        print("DEBUG mode, DES correct")
        print("DES exit")

    else:
        if len(sys.argv) != 2:
            print("Exactly one argument is expected (either -e or -d)")
            exit(1)
        else:
            mode = sys.argv[1]
            data_folder = None
            if mode == "-e":
                print("Encryption mode")
                des = Des(encryption=True)
                data_folder = DATA_SOURCE
                output_folder = OUTPUT_DIR

                #key genaration 64-bit length
                generated_key = des.create_key()
                with open(KEY_FILEPATH, 'w') as file:
                    file.write(generated_key)

                # TODO call Des function to create a key and store it to the KEY_FILEPATH

            elif mode == "-d":
                print("Decryption mode")
                des = Des(encryption=False)
                data_folder = OUTPUT_DIR
                output_folder = DECODED_DIR
            else:
                print("Unknown mode... Choices are [-e, -d]")
                exit(1)

            if os.path.exists(data_folder):
                files = sorted(os.listdir(data_folder))
                print(f"{len(files)} files found in {data_folder}")
                for file in files:

                    if mode == "-e":
                        file_full_name = os.path.basename(file).split(".")

                        file_name = file_full_name[0]
                        file_extension = file_full_name[1]
                    elif mode == "-d":
                        file_full_name = os.path.basename(file).split(".")

                        split_index = file_full_name[0].rfind("_")
                        file_name = file_full_name[0][:split_index]
                        file_extension = file_full_name[0][split_index + 1:]

                        # print(file_name)
                        # print(file_extension)

                    with open(data_folder + "\\" + file, 'rb') as file_to_read:
                        file_bytes = file_to_read.read()
                    input_bytes = file_bytes

                    with open(KEY_FILEPATH, 'r') as file_key:
                        text = file_key.read()

                    key = int(text, 16)

                    print(f"Processing file {file}")
                    output_bytes = des.perform_des(input_bytes=input_bytes, key=key)

                    if des.encryption:
                        # TODO build output_filename
                        with open(output_folder + "\\" + file_name + "_" + file_extension + ".des", 'wb') as file_out:
                            file_out.write(output_bytes)
                        pass
                    else:
                        with open(output_folder + "\\" + file_name + "." + file_extension, 'wb') as file_out:
                            file_out.write(output_bytes)
                        pass

                    #TODO save output bytes to the proper file based on encryption or decryption