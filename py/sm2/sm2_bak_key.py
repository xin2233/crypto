from sm2_genkey import *
from sm3_hash import sm3_hash

if __name__ == '__main__' :
    """
    date: 2023-11-24
    usage: 
    brief: according to sm2_key.c generate bin file 
    """

    # ***** 
    # modify this if you need
    sm2_key_c_file_path = "./sm2_key.c"
    # *******

    # get pub_array, pri_array, pub_dig_array
    pub1, pri2, pdig3 = get_array_key_str_from_c_file(sm2_key_c_file_path)
    pub_str_shift = arry_convert(pub1)
    pri_str = arry_convert(pri2)
    p_dig_str_shift = turn_round(arry_convert(pdig3))


    # write file 
    # hash string  digest, sm2_pub_key_digest
    hash_bin_file = bytes.fromhex(p_dig_str_shift)

    with open('1_sm2_pub_key_digest.bin', 'wb') as f:
            f.write(hash_bin_file)

    with open('1_sm2_pub_key.bin', 'wb') as f:
        f.write(bytes.fromhex(turn_round(pub_str_shift)))

    with open('1_sm2_pri_key.bin', 'wb') as f:
        f.write(bytes.fromhex(turn_round(pri_str)))

    print("recover bin according to c file, done!")