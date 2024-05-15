import os
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import time
import sys
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives import hashes

# 需要時間
# key等等可自由決定
# aes-ccm : https://cryptography.io/en/3.4.8/hazmat/primitives/aead.html
# aes-ctr : https://cryptography.io/en/3.4.8/hazmat/primitives/symmetric-encryption.html#cryptography.hazmat.primitives.ciphers.modes.CTR
# ChaCha20 : https://cryptography.io/en/3.4.8/hazmat/primitives/symmetric-encryption.html
# SHA-3-512 ： https://cryptography.io/en/3.4.8/hazmat/primitives/cryptographic-hashes.html

def aes_ccm(data):
     print("~~~~~~~~~~AES-CCM 加密~~~~~~~~~~\n")
     aad = b"authenticated but unencrypted data"
     key = AESCCM.generate_key(bit_length=128)
     aesccm = AESCCM(key)
     nonce =  os.urandom(11) #根據範例的長度給到13會報錯：ValueError: Nonce too long for data

     # 在加密前後加入時間以計算耗時
     start_time = time.perf_counter()
     ct = aesccm.encrypt(nonce, data, aad)
     end_time = time.perf_counter()
     elapsed_time = end_time - start_time
     print("AES-CCM加密時間為 {} 秒, 加密後檔案大小為 {} bytes\n".format(elapsed_time, sys.getsizeof(ct)))
     print("每秒加密 {} bytes\n".format(len(data)/elapsed_time))

     de_data = aesccm.decrypt(nonce, ct, aad)
     if(de_data == data):
          print("加密前後檔案一致\n")
     else:
          print("加密前後檔案不一致\n")

def aes_ctr(data):
     print("~~~~~~~~~~AES-CTR 加密~~~~~~~~~~\n")
     key = os.urandom(32)
     iv = os.urandom(16)
     cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
     encryptor = cipher.encryptor()

      # 在加密前後加入時間以計算耗時
     start_time = time.perf_counter()
     ct = encryptor.update(data) + encryptor.finalize()
     end_time = time.perf_counter()
     elapsed_time = end_time - start_time
     print("AES-CTR加密時間為 {} 秒, 加密後檔案大小為 {} bytes\n".format(elapsed_time, sys.getsizeof(ct)))
     print("每秒加密 {} bytes\n".format(len(data)/elapsed_time))

     decryptor = cipher.decryptor()
     de_data = decryptor.update(ct) + decryptor.finalize()

     if(de_data == data):
          print("加密前後檔案一致\n")
     else:
          print("加密前後檔案不一致\n")

def chacha20(data):
     print("~~~~~~~~~~ChaCha20 加密~~~~~~~~~~\n")
     nonce = os.urandom(16)
     key = os.urandom(32)
     algorithm = algorithms.ChaCha20(key, nonce)
     cipher = Cipher(algorithm, mode=None)
     encryptor = cipher.encryptor()

      # 在加密前後加入時間以計算耗時
     start_time = time.perf_counter()
     ct = encryptor.update(data)
     end_time = time.perf_counter()
     elapsed_time = end_time - start_time
     print("ChaCha20加密時間為 {} 秒, 加密後檔案大小為 {} bytes\n".format(elapsed_time, sys.getsizeof(ct)))
     print("每秒加密 {} bytes\n".format(len(data)/elapsed_time))

     decryptor = cipher.decryptor()
     de_data = decryptor.update(ct)

     if(de_data == data):
          print("加密前後檔案一致\n")
     else:
          print("加密前後檔案不一致\n")

def sha_3_512():
     string = 'I love cryptography.'
     print("~~~~~~~~~~SHA-3-512 message digest~~~~~~~~~~\n")
     digest = hashes.Hash(hashes.SHA3_512())
     digest.update(string.encode())
     ans = digest.finalize()
     print(ans.hex())


if __name__ == '__main__':
     file_name = 'test.pdf'
     with open(file_name, 'rb') as file:
          data = file.read()
     print("檔案原始大小為 {} bytes\n".format(sys.getsizeof(data)))

     aes_ccm(data)
     aes_ctr(data)
     chacha20(data)
     sha_3_512()
