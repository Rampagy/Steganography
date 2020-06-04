from PIL import Image
import numpy as np


class Steganography():
    def __init__(self, encoding_bits=1, repeat=True, color_bits=8):
        # (color_bits / encoding_bits) must be an integer
        assert color_bits/encoding_bits == int(color_bits/encoding_bits)

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





if __name__=='__main__':
    im = np.array(Image.open('./image-analysis.png'))

    steg = Steganography()
    encoded_img = steg.encode(im, 'Steganography ')

    result = Image.fromarray(encoded_img)
    result.save('Encoded.png')

    msg = steg.decode(encoded_img)
    print(msg[:500])