from PIL import Image
from Crypto.Cipher import AES as AES_obj
import os
import argparse

key = b'1234567812345678'
nonce = b'cda235a2'
ppm_name = 'temp.ppm'
ppm_encrypt_name = 'encrypt.ppm'

def str_xor(s1 :str, s2 :str):
    return bytes([b1 ^ b2 for b1, b2 in zip(s1, s2)])

def counter(i : int):
    """the counter block for ctr mode
    
    Args:
        i: the i-th counter block
    Returns:
        the 16-byte long byte string
    """
    global nonce
    i = int(i)
    count = []
    for _ in range(8):
        count.append(int(i % 256))
        i = int((i - (i % 256)) / 256)
    count.reverse()
    count = bytes(count)
    return nonce + count

def ppm2png(from_name:str, to_name:str):
    """convert ppm file to png file
    
    Args:
        from_name: the name of input ppm file
        to_name: the name of output png file
    """
    im = Image.open(from_name)
    im.save(to_name)
    im.close()

def img2ppm(img_name: str):
    """convert img file(.jpeg, .jpg, .png) to .ppm file
    
    Args:
        img_name: the name of image
    """
    global ppm_name
    im = Image.open(img_name)
    im.save(ppm_name)
    im.close()

def writePPM(data :str):
    """write the binary data to ppm file
    
    Args:
        data: the bytes, expected str type
    """
    with open(ppm_encrypt_name, 'wb') as f:
        f.write(data)
def processPPM(block_size):
    """Process the PPM file
    
    detach the ppm information(e.g the length and width) from the ppm file, and then do padding to fit the AES block size
    
    Returns:
        A tuple(img_information, img_pixels), the two variable is string type.
    """
    global ppm_name
    with open(ppm_name, 'rb') as f:
        data = f.readlines()
    img_info = b"".join(data[:3])
    img_pixels = b"".join(data[3:])
    #padding
    pad_block_num = block_size - (len(img_pixels) % block_size)
    symbol = bytes(chr(pad_block_num),encoding="ascii")
    img_pixels += (symbol * pad_block_num)
    return img_info, img_pixels


def ECB(cipher,text,oper):
    cipher_fun = None
    block_size = cipher.block_size
    result = b''
    
    if oper == "encrypt":
        cipher_fun = cipher.encrypt
    elif oper == "decrypt":
        cipher_fun = cipher.decrypt
    
    for i in range(0, len(text), block_size):
        block = text[i:i + block_size]
        result += cipher_fun(block)
    
    return result

def CTR(cipher,text,oper):
    block_size = cipher.block_size
    result = b''

    for i in range(0, len(text), block_size):
        counter_block = cipher.encrypt(counter(i / block_size))
        result += str_xor(text[i:i+block_size], counter_block)
    return result

def CBC(cipher,text,oper):
    block_size = cipher.block_size
    result = b''
    last_block = counter(0)
    if oper == "encrypt":
        for i in range(0, len(text), block_size):
            cur_block = cipher.encrypt(str_xor(last_block, text[i:i+block_size]))
            last_block = cur_block
            result += cur_block
    elif oper == "decrypt":
        for i in range(0, len(text), block_size):
            cur_block = text[i:i+block_size]
            result += str_xor(last_block, cipher.decrypt(cur_block))
            last_block = cur_block
    return result

def OFB(cipher,text,oper):
    block_size = cipher.block_size
    result = b''
    block = counter(0)
    for i in range(0, len(text), block_size):
        block = cipher.encrypt(block)
        result += str_xor(block, text[i:i+block_size])
    return result

def COOL(cipher,text,oper):
    global nonce
    block_size = cipher.block_size
    result = b''
    last_block = counter(0)
    
    IV = nonce * 2
    batchs = [c for c in IV if c != 0]
    if batchs == 0:
        batchs = [int(len(text) / block_size) + 1]

    last_block = IV
    now_batch = 0
    num = batchs[0]
    if oper == "encrypt":
        for i in range(0, len(text), block_size):
            if num == 0:
                now_batch = (now_batch + 1) % len(batchs)
                last_block = IV
                num = batchs[now_batch]
            cur_block = cipher.encrypt(str_xor(last_block, text[i:i+block_size]))
            last_block = cur_block
            result += cur_block
            num -= 1
            
    elif oper == "decrypt":
        for i in range(0, len(text), block_size):
            if num == 0:
                now_batch = (now_batch + 1) % len(batchs)
                last_block = IV
                num = batchs[now_batch]
                
            cur_block = text[i:i+block_size]
            result += str_xor(last_block, cipher.decrypt(cur_block))
            last_block = cur_block
            num -= 1
    return result
def AES(file_name,output_name,mode,oper):
    """do AES encryption or decryption

    Args:
        file_name: the input file name, expected a img file
        output_name: the result of encrytion or decryption
        mode: the block cipher mode, there are five option:ECB, CTR, CBC, OFB, COOL
        oper: decryption or encrytion, 'e' or 'encryption' means encryption, 'd' or 'decryption' mean decryption
    """
    global key
    mode = mode.upper()
    oper = oper.lower()
    cipher = AES_obj.new(key, AES_obj.MODE_ECB)
    img2ppm(file_name)
    img_info, img_pixels = processPPM(cipher.block_size)
    
    
    fun = None
    if mode == "ECB":
        fun = ECB
    elif mode == "CTR":
        fun = CTR
    elif mode == "CBC":
        fun = CBC
    elif mode == "OFB":
        fun = OFB
    elif mode == "COOL":
        fun = COOL
    else:
        raise ValueError("This block cipher mode does not exist!")
    if (oper == 'e' or oper == 'encrypt'):
        oper = 'encrypt'
    elif (oper == 'd' or oper == 'decrypt'):
        oper = 'decrypt'
    else:
        raise ValueError("This operation is illegal!")
    result = fun(cipher, img_pixels,oper)
    result = img_info + result
    writePPM(result)
    ppm2png(ppm_encrypt_name, output_name)
    #remove the ppm file
    os.remove(ppm_name)
    os.remove(ppm_encrypt_name)
    
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("file_name", help="the input file name ,which you want to encrypt or decrypt")
    parser.add_argument("-o", help="the output file name, must be a image name",default="output.png")
    parser.add_argument("-m", help="the block cipher mode, there are five options: 'OFB', 'CBC','ECB','OFB','COOL')", default="ECB")
    parser.add_argument("-e", help="encrypt file or decrypt file, you can input the full operation name, just like \
                                    'encrypt' or 'decrypt'.And you can type the short name, 'e' means encrypt and 'd'\
                                     means decrypt"
                              ,default="e")
    args = parser.parse_args()
    return args


def main_fun():
    args = get_args()
    AES(args.file_name, args.o, args.m, args.e)

if __name__=="__main__":
    main_fun()

