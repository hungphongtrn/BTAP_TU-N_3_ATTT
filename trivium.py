from collections import deque
from itertools import repeat
from bitstring import BitArray

class Trivium:
    def __init__(self, key, iv):
        self.state = None
        self.key = key
        self.iv = iv

        # Initialize ks list to store keystream 
        self.ks = []

        # Initialize state
        # (s1; s2; : : : ; s93) (K1; : : : ; K80; 0; : : : ; 0)
        init_state = self.key
        init_state += list(repeat(0, 13))

        # (s94; s95; : : : ; s177) (IV1; : : : ; IV80; 0; : : : ; 0)
        init_state += self.iv
        init_state += list(repeat(0, 4))

        # (s178; s179; : : : ; s288) (0; : : : ; 0; 1; 1; 1)
        init_state += list(repeat(0, 108))
        init_state += [1, 1, 1]

        self.state = deque(init_state)

        # Do 4 Full cycle clock
        for i in range(4 * 288):
            self.gen_keystream()

    def gen_keystream(self):
        #Trivium keystream generate algorithms
        t_1 = self.state[65] ^ self.state[92]
        #print(t_1)
        t_2 = self.state[161] ^ self.state[176]
        #print(t_2)
        t_3 = self.state[242] ^ self.state[287]
        #print(t_3)

        z = t_1 ^ t_2 ^ t_3

        t_1 = t_1 ^ self.state[90] & self.state[91] ^ self.state[170]
        t_2 = t_2 ^ self.state[174] & self.state[175] ^ self.state[263]
        t_3 = t_3 ^ self.state[285] & self.state[286] ^ self.state[68]

        self.state.rotate()

        self.state[0] = t_3
        self.state[93] = t_1
        self.state[177] = t_2

        return z

    def keystream(self, msglen):
        # Generete keystream
        counter = 0
        keystream = []

        while counter < msglen:
            keystream.append(self.gen_keystream())
            counter += 1

        return keystream

    def encrypt(self, msg):
        all_cipher = []

        for i in range(len(msg)):
            #Get hex of msg ascii
            hex_plain = hex(ord(msg[i]))
            plain = BitArray(hex_plain)
            plain.byteswap()

            #Get keystream binary
            keystream = self.keystream(8)
            self.ks += keystream[::-1]
            keystream = '0b' + ''.join(str(i) for i in keystream[::-1])
            keystream = BitArray(keystream)
            keystream.byteswap()


            #Message XOR keystream
            cipher = [x ^ y for x, y in zip(map(int, list(plain)), map(int, list(keystream)))]
            all_cipher += cipher

            #Print elements
            # cipher = '0b' + ''.join(str(i) for i in cipher)
            # cipher = BitArray(cipher)
            # cipher.byteswap()
            #
            # print('{: ^15}{: ^15}{: ^15}{: ^15}{:^15}'.format(hex_plain, plain.bin, keystream.bin, cipher.bin,
            #                                             '0x' + cipher.hex.upper()))

        return all_cipher

    def decrypt(self, cipher):
        #Cipher XOR keystream
        all_plain = [x ^ y for x, y in zip(map(int, cipher), map(int, self.ks))]
        return all_plain

def bitToString(bits):
    #Convert list of bits to string
    bit_string = ''.join(map(str, bits))  # Convert bits to a string of 0s and 1s
    byte_string = ''.join([chr(int(bit_string[i:i + 8], 2)) for i in range(0, len(bit_string), 8)])  # Convert 8-bit chunks to bytes and join them
    return byte_string

def main():
    
    # Initialize Trivium
    KEY = BitArray("0x0F62B5085BAE0154A7FA")
    print("Key : ", KEY.hex)
    KEY.byteswap()
    KEY = list(map(int, KEY.bin))

    IV = BitArray("0x288FF65DC42B92F960C7")
    print("IV : ", IV.hex)
    IV.byteswap()
    IV = list(map(int, IV.bin))

    trivium = Trivium(KEY, IV)
    trivium.gen_keystream()

    #Get message from user
    msg = input("Enter your message: ")
    print("plain text: " + msg)

    


    #Encrypt message
    cipher = trivium.encrypt(msg)
    print("keystream: " + str(trivium.ks))

    #Print 256bit keystream
    key_string = ''.join(map(str, trivium.keystream(256)))  # Convert bits to a string of 0s and 1s
    print("keystring: " + key_string)

    print("cipher: " + str(cipher))
    print("cipher text: " + bitToString(cipher))

    #Decrypt cipher
    decrypt = trivium.decrypt(cipher)
    # print("decrypted: " + str(decrypt))
    print("decrypt to text: " + bitToString(decrypt))

    print()

if __name__ == "__main__":
    main()