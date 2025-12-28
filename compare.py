bit1 = b"11110001001111001001101011100100100100111000100010100110110001"
bit2 = b"11110001001111001001101011100100100100111000100010100110110001"
bit1_str = bit1.decode()
bit2_str = bit2.decode()
bit1_int = int(bit1_str, 2)
bit2_int = int(bit2_str, 2)
result = bit1_int ^ bit2_int
print(bin(result)[2:].zfill(64).count("1"))