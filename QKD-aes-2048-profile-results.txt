Profiling AES-2048 Encryption:
         11596 function calls (10970 primitive calls) in 12.131 seconds

   Ordered by: cumulative time
   List reduced from 212 to 10 due to restriction <10>

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.000    0.000   12.131   12.131 <ipython-input-2-aa4158ac226c>:46(aes_2048_encrypt)
        1    0.000    0.000   12.128   12.128 /usr/local/lib/python3.11/dist-packages/Crypto/Protocol/KDF.py:100(PBKDF2)
       13    0.000    0.000   12.117    0.932 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/HMAC.py:130(_pbkdf2_hmac_assist)
       13   12.117    0.932   12.117    0.932 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/SHA1.py:168(_pbkdf2_hmac_assist)
       26    0.001    0.000    0.009    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/HMAC.py:72(__init__)
       13    0.000    0.000    0.008    0.001 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/HMAC.py:219(new)
      261    0.000    0.000    0.005    0.000 /usr/local/lib/python3.11/dist-packages/cffi/api.py:242(new)
       52    0.000    0.000    0.004    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/SHA1.py:148(new)
      261    0.000    0.000    0.004    0.000 /usr/local/lib/python3.11/dist-packages/cffi/api.py:180(_typeof)
      143    0.001    0.000    0.004    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/SHA1.py:72(__init__)




Profiling AES-2048 Decryption:
         5352 function calls (5333 primitive calls) in 14.411 seconds

   Ordered by: cumulative time
   List reduced from 67 to 10 due to restriction <10>

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.000    0.000   14.411   14.411 <ipython-input-2-aa4158ac226c>:71(aes_2048_decrypt)
        1    0.000    0.000   14.410   14.410 /usr/local/lib/python3.11/dist-packages/Crypto/Protocol/KDF.py:100(PBKDF2)
       13    0.000    0.000   14.402    1.108 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/HMAC.py:130(_pbkdf2_hmac_assist)
       13   14.401    1.108   14.402    1.108 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/SHA1.py:168(_pbkdf2_hmac_assist)
       26    0.001    0.000    0.007    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/HMAC.py:72(__init__)
       13    0.000    0.000    0.004    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/HMAC.py:140(copy)
       52    0.001    0.000    0.004    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Util/strxor.py:48(strxor)
       13    0.000    0.000    0.003    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Hash/HMAC.py:219(new)
      293    0.000    0.000    0.003    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Util/_raw_api.py:142(c_uint8_ptr)
      293    0.002    0.000    0.002    0.000 /usr/local/lib/python3.11/dist-packages/Crypto/Util/py3compat.py:145(byte_string)




Memory Usage During Encryption:
Memory used: 0.56640625 MB

System Usage Metrics:
CPU Usage: 3.0%
Memory Usage: 10.3%
