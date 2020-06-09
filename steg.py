import base64
import hashlib
import re

import numpy as np
from Crypto import Random
from Crypto.Cipher import AES
from PIL import Image


class Steganography():
    def __init__(self, encoding_bits=1, repeat=True, color_bits=8):
        # (color_bits / encoding_bits) must be an integer
        assert color_bits/encoding_bits == int(color_bits/encoding_bits)

        # steganography settings
        self.cnt = 0
        self.decoded = []
        self.repeat = repeat
        self.encoding_bits = encoding_bits
        self.encoding_mask = pow(2, encoding_bits) - 1
        self.color_bits = color_bits


    def encode(self, img, msg):
        '''
        img is numpy array of image
        msg is text to be hidden in image
        returns numpy array of encoded image
        '''

        self.cnt = 0
        for r, row in enumerate(img):
            for c, col in enumerate(row):
                R = self.encrypt_color(col[0], msg)
                G = self.encrypt_color(col[1], msg)
                B = self.encrypt_color(col[2], msg)

                img[r, c] = (R, G, B)
        return img


    def decode(self, img):
        '''
        img is numpy array of image
        returns string of decoded message
        '''

        num_bytes = int(img.size / self.color_bits) * self.encoding_bits
        self.decoded = [0] * num_bytes
        self.cnt = 0

        for row in img:
            for col in row:
                self.decrypt_color(col[0])
                self.decrypt_color(col[1])
                self.decrypt_color(col[2])

        return ''.join( map(chr, self.decoded) )


    def encrypt_color(self, by, msg):
        if self.cnt / self.color_bits >= len(msg) and not self.repeat:
            return by
        else:
            if self.repeat:
                char = ord( msg[int(self.cnt / self.color_bits) % len(msg)] )
            else:
                char = ord( msg[int(self.cnt / self.color_bits)] )

            bit_pos = self.color_bits - (self.cnt % self.color_bits) - self.encoding_bits
            bit = char & (self.encoding_mask << bit_pos)
            new_bit = bit >> bit_pos

            new_pix = (~self.encoding_mask & by) | new_bit
            self.cnt += self.encoding_bits
            return new_pix


    def decrypt_color(self, by):
        bit_pos = self.color_bits - (self.cnt % self.color_bits) - self.encoding_bits
        encoded_bit = (by & self.encoding_mask) << bit_pos

        char_pos = int(self.cnt / self.color_bits)

        self.decoded[char_pos] = self.decoded[char_pos] | encoded_bit
        self.cnt += self.encoding_bits
        return


class AES_helper():
    def __init__(self,  key='password'):
        self.block_size = AES.block_size
        self.key = self.set_key(key)


    def set_key(self, key):
        return hashlib.sha256(key.encode()).digest()


    def AES_encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))


    def AES_decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[self.block_size:])).decode('utf-8')


    def _pad(self, s):
        return s + (self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size)


    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]



if __name__=='__main__':
    # create class for encrypting
    k = 'super secret key'
    AES_help = AES_helper(key=k)
    steg = Steganography()

    # encrypt the message with AES\
    AES_encrypted = AES_help.AES_encrypt('top secret message')
    AES_encrypted = 'encryption=AES, block_size=16, key={key}, message='.format(key=k) + AES_encrypted.decode('utf-8') + '; '

    # encode the picture with the text
    im = np.array(Image.open('./image-analysis.png'))
    encoded_img = steg.encode(im, AES_encrypted)

    # save the image
    result = Image.fromarray(encoded_img)
    result.save('Encoded.png')

    # find the encoded message and key
    text = steg.decode(encoded_img)
    message = re.search('message=(.*); ', text[:150]).group(1)
    AES_help.key = AES_help.set_key(re.search('key=(.*), message=', text[:150]).group(1))

    # decrypt the encrypted message
    decrypted_message = AES_help.AES_decrypt(message)
    print(decrypted_message)

    '''
    steg = Steganography()
    im = np.array(Image.open('./LookAndYouShallSee.png'))
    text = steg.decode(encoded_img)
    print(text[:150])
    '''
