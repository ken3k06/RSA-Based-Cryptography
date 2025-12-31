bit1 = b"1010101100100110110011011000000010010111110111100100110001100001"
bit2 = b""
bit1_str = bit1.decode()
bit2_str = bit2.decode()
bit1_int = int(bit1_str, 2)
bit2_int = int(bit2_str, 2)
result = bit1_int ^ bit2_int
print(bin(result)[2:].zfill(64).count("1"))