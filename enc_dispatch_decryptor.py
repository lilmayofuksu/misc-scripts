#!/usr/bin/env python3

"""
    Copyright (C) 2022  Nobody

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import base64

import json
import traceback
from xml.etree import ElementTree as etree

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def conv_num(num):
    num = base64.b64decode(num)
    num = ''.join(['{:02x}'.format(x) for x in num])
    num = int(num, 16)
    return num

def get_params_from_xml(xml, params):
    return tuple([conv_num(xml.find(p).text) for p in params])

def get_key_from_xml(s, params):
    xml = etree.fromstring(s)
    params = get_params_from_xml(xml, params)
    return RSA.construct( params )

def get_pub_key_from_xml(s):
    return get_key_from_xml(s, ['Modulus', 'Exponent'])

def get_priv_key_from_xml(s):
    return get_key_from_xml(s, ['Modulus', 'Exponent', 'D', 'P', 'Q'])

def verify(message, sign, key):
    signer = pkcs1_15.new(key)
    digest = SHA256.new(message)
    signer.verify(digest, sign) # Throws an exception in the case of invalid signature

def do_sign(message, key):
    signer = pkcs1_15.new(key)
    digest = SHA256.new(message)
    return signer.sign(digest)

if __name__ == '__main__':

    server_response = json.loads(input("Please enter the server response: "))
    #server_response = json.loads('{"content":"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","sign":"duEsPIG6/J3UGJS6Mc0HFJLDqcdUrixs74igfP5KN3RTGkTHNJWQz0yxIQLdztQRI0mnE1LxMKbQBgUwEs8RmIqMnBelQrIXRXc0vL/Ge0/PQ2zfhFwylsgQ6ulOD79/UfEX0+oxN1HTKH0eHkVgiayplHAy8qMZVRnKBMBuDeqUmK2S4V/dZAsMAtwuwJhalWTJVr2JyboaZNLRhElnInysEE8ZaVNYtXQS1TJdzDQRmh6xhRKHP4n+qaRVb3E6PTtaOGCpSRajf6rP2RJ4rDRDw0U7sIUMG+0IYSyTHDsJzkM6YOcBnyKZMRWRAqDNUNdw0Iztp7FCxQHgEpQt4w=="}')
    key_type = input("Please enter the encryption key type (2 for CN, 3 for Global, 5 for Global Beta???, 'sign' for GC Signing Key <for decrypting client seed>): ")
    sign_key_type = input("Please enter the sign key type (2 for CN, 3 for Global, 5 for Global Beta???, 'sign' for GC Signing Key): ")

    content = None
    sign = None

    keys = {
        "1": {
            "publicRSAKey": "<RSAKeyValue><Modulus>4dwQDDcitJ97u1yMTCSddaMk1tZEkFBmh5cjfz0PndE+BJp0aayuIPMtkFuG2gPL0GBpIO77BNXTgt/bbvPY/3SgI8wf8lClqSOHErmekbpvD8c/D8mrH6NP1adcC/Jciz7v0ogeqJnw2azAyXRki4vvEpIBsXWq+rt1xCLAGyr5j9j/CpoO2IuUb5XKIN94Jiz+h4nlw0mSFMPCUv/V3EmhmOD/g8ya40XBNDY5g7HkBkHy55kjFnf6e12gxyI88i5vgrtcEFyWsGdtydQezQdgVp5qwGeW5BL9QbIVJ/p8AgnS1gEgwPJOg9WY9AZcHVGghOZ4Vei+RXQajzcnWw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "privateRSAKey": "<RSAKeyValue><Modulus>xAde3Gos++LVlw2vvW5OiziD97fVvA3Y6GLY0xMd4d7LpnHrfwuO7+60IZA9zR6QOFkrMrxNMTf2UbEJsnfbnUyhsQJr8bHR6PfUj6d/YUceM8YWcjpCyZGM2mKuVBXYqWO8gU81bwQOKgHSytvIrXtsk+3+g+pfkSKZOakiPzosSXCtGSPrVRJlumCmiXjTiKiwKqR+BBk8tZSuINl+r/aTfgu5xkfcB6YOYIIsNfkhpyZTcO0TNk7A3gRhikySyfxZX/T7lBDqUUKMMoCPy8MPGHvc66YyW1xsf02zdkAHXDzchj6TrzApvzrUzEcl9rwxzCEtGWh5wjIV1a/sJQ==</Modulus><Exponent>AQAB</Exponent><P>/HcDx3kyHFcCtOXefbE10IoNxJm7gwbkELGZzvTKsLj4xReEyizzW/JS3P2zgdFwmWqgj7a2vQmm1VoRaM375UUphVbiL6df5hNuqd1DW2Bepdca4tODp996ZC3CYqg6Y1+rkVcy4LPJIbT5gyn6VG6EdpMINPma+EWeCmRSNZ8=</P><Q>xsYOFP4pxu8kAGfU/n95LZycN5ttwFQRUTRRMXyNaysY1B0+PqhXZemN+OU9HnJtElt4kjy4N09RQB7KvhM07Ccm/IztPWzGSbzOYshSjq+w1dBP8djJoUVMp+1gAD1XcAHft61IAsofiDlRUbqV9m4mWnTzA+UarzjO/f+Ln7s=</Q><DP>LFvQ+yxtRJN5M0WsWRNY7EJFdwS38Ka2TcSWzMkwD+sAMskWGNvbCo3CR3gAIVAmY55bhcTJyN84RAZmRq7ikn8bc4U3ir3y2J8Tc58f5Z9CIgtweuhFGqrme1Ga9PCwCaPWplvW4apVLan5qTUn+cvNVHQzHfO5aeP5h8Pmues=</DP><DQ>M3FUeahhpYOEfLpijE7vTJeocle+arUXGj4A+V6zttWbgmHjFxI4ND7iqFSjobqZcdPMe4RNZLsZWw/dBp4v5yIm29uZFnmNQ84iV7xiaV0c1ekol320iRFHSnqLiuRVOb6yaHXnGhm3WWkEG7O/Vdyh/m0f65Uid9Cq+V9mgjs=</DQ><InverseQ>gfQo6fET7ixHs/CEm7Kmmq/7NZel1WzwF++13lbpCY1yl390jeEWrQYvzgC0pHfU8XCK6n0PEybQ4nM/AiQt+/f4YX8fZ8Tf2UsgH+tKmeCkXO6hLU0yLRsaXWAs+6QFF0e+A+cNU+jm+U2CMjItlnn3cw8fiKNMmalIxG6rnS8=</InverseQ><D>sx0w9iEl3TnUg+MDkwj5R4hqPKyC5QOaECxRhfvPsBSM7BbnYPxErMLlYE2VypiEmpgPOpqHxdMmhFpJTALsbfwZOc3Gp98ct8vLMz+OymnbFN+InvLRF7CgjOLh+v7DK3NwSI8BeeCwuH1WB/lukeVWvowVpJ9AlzKP4vnByxZWFfGEnG5Tvp5oY8SODvbMvG+oK0NfxDB4vIqDovuMNFWSw+dhlbEOerQH++RDhQLGYM5XTB0zQnbwwMtTXjV4J4jeqhb+766gn0dQ1oeIy8s3i3ZOnOM2pKM0ohJZ2Pjzkbsz1rvhgAWeqmDA6Q5RgK4kRtWPJRtDuJySvk+CeQ==</D></RSAKeyValue>"
        },        
        "2": {
            "publicRSAKey": "<RSAKeyValue><Modulus>wt/Z98o8gbw94la07B1/ApVCuHWHGI7Pd8FPF3PvNYf1oTYwgRczQBfPqHfXyttRRP44mqG4tfrz2zO8gXENRSyDXtzu7dQGh3hu1t87TpPbiYcQ+ZHK58v6dy1jo30TTK64sRnjxJfWrKYDxSBxBzDbKClzqlY0J/4mVjKFxk7qS0HvoYydlRnhvJVOMdjt/SV6wyHRY66FvOvdk6BVLom3K0WBHNcFE6ChA3GQcR+xyX1Z058AviFrx6KS45mqRujUC5vZXuwbvgrICgEVlfOScHFnrTlFX8ysM4C1bSb8Icy3V8XSb7LjCmXBeB7TUpW2vjhKlzgZeWwNu1DaEw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "privateRSAKey": "<RSAKeyValue><Modulus>z/fyfozlDIDWG9e3Lb29+7j3c66wvUJBaBWP10rB9HTE6prjfcGMqC9imr6zAdD9q+Gr1j7egvqgi3Da+VBAMFH92/5wD5PsD7dX8Z2f4o65Vk2nVOY8Dl75Z/uRhg0Euwnfrved69z9LG6utmlyv6YUPAflXh/JFw7Dq6c4EGeR+KejFTwmVhEdzPGHjXhFmsVt9HdXRYSf4NxHPzOwj8tiSaOQA0jC4E4mM7rvGSH5GX6hma+7pJnl/5+rEVM0mSQvm0m1XefmuFy040bEZ/6O7ZenOGBsvvwuG3TT4FNDNzW8Dw9ExH1l6NoRGaVkDdtrl/nFu5+a09Pm/E0Elw==</Modulus><Exponent>AQAB</Exponent><P>9hdURxe6DnOqSpe6nh2nVLTmxrPXNY+FSFCb4KtuGB5OqmOeAkkQHv2oysabKSLQ/9wa1tNysd/z6LuAOUgZbQ4xvj+Ofh/kAJUPTSLK+QdIY+fQCKYyg04xuQai3tKRKedzDFd1rDAPJO7Z2h9e4Gvvb4ZiqBEAbnYi4DQLSlE=</P><Q>2Fen9TJb+G0Hbt+spyH+tMpAqbXaQFXbQCSRFRBSJuKJDJa55Yqz7ltVpblHmgMiFbGp+0m2cQVZS9ZpMekewH9umNLcInpaSeo1ulrdAhJylXW7DxX4S3P8rb9+2PJnMWiepz4m53nfrjEV0iU6xGP2BmcrzdZy6LoQXEB6vmc=</Q><DP>nNPPNKMtQep6OqEpH3ycV4IVk8mmO47kDGq6e9okBiDCVxm255PyPx2+BMO+u99hO7zkKcWE0VB8WvOqylZlRbeHAcv1HfFq1ugnYSvsF/mJK4nebLSlekJJs7VD9CZStla2XcYayomyDQJeOQBG8VQ3uWX1109GbB7DKQhhrZE=</DP><DQ>cmKuWFNfE1O6WWIELH4p6LcDR3fyRI/gk+KBnyx48zxVkAVllrsmdYFvIGd9Ny4u6F9+a3HG960HULS1/ACxFMCL3lumrsgYUvp1m+mM7xqH4QRVeh14oZRa5hbY36YS76nMMMsI0Ny8aqJjUjADCXF81FfabkPTj79JBS3GeEM=</DQ><InverseQ>F5hSE9O/UKJB4ya1s/1GqBFG6zZFwf/LyogOGRkszLZd41D0HV61X3tKH3ioqgkLOH+EtHWBIwr+/ziIo1eS9uJo/2dUOKvvkuTpLCizzwHd4F+AGG0XID0uK1CpdaA5P3mDdAjWAvw2FfbAL+uZV/G9+R2Ib1yElWLcMELv/mI=</InverseQ><D>rR9ewnJPiiUGF49vcahuKspDVA2sGyC4igjJARO+ed1qv1HI5rrkeG1ZzC/LnEt5oEfwYB1d5fL1Cp8b6kcf6BmZFjWs24rsC/k4QG5S1qqxJmLmVQqEHAJ75E/LSKg1s+34QxLmZ55DM2XAEyGc4GVEmuSHz97t6z/jK1W8mgncyRHiNGK79V0/jOXXZCkK2IKguZEYmIvy4zXCyYaklbfKd+wnScdTxhxYyim+DGaQDZTUYHk7VqRlX0tDyS82oiNTcj0ib+8VmYFYWyvfsEMakhuipmeL6RL0SNcyoqL+QbABTfhn7g+ZqZ9V6PQqc034/7Dtd1aRx/jLfNPsgQ==</D></RSAKeyValue>"
        },
        "3": {
            "publicRSAKey": "<RSAKeyValue><Modulus>yYlF2xKeHRDZUSsXlLoSk/YAb2oIOwpbUeO4I+5GfWoybSpde4UnOlZgpKIDgltF3e9ST8bqIwuBxMoJTpOAnEKLNuBDdSeefHwhFqdczgeETxySwFKScmti1QRwgacrlgWglmaYCaeQrqbBceF9JbF4npi6S3+eFpw0j4rPjlE3vjh1AopaZQWAHGZI8Ixr7LDebe/uF8i7OCWXpkPKUTJnCEpyqM5H+pLN3MWRiL7mBR4XFqwKQr8J27Y3LN1iX9927hMsvAnh9PWoHzqpDTqIBF7w1ifYs3XQ3EMbf0zqc26UZXUaI5pD6qXNm3STz94SrfYqYY1R3Npz/Syaww==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "privateRSAKey": "<RSAKeyValue><Modulus>02M1I1V/YvxANOvLFX8R7D8At40IlT7HDWpAW3t+tAgQ7sqjCeYOxiXqOaaw2kJhM3HT5nZll48UmykVq45Q05J57nhdSsGXLJshtLcTg9liMEoW61BjVZi9EPPRSnE05tBJc57iqZw+aEcaSU0awfzBc8IkRd6+pJ5iIgEVfuTluanizhHWvRli3EkAF4VNhaTfP3EkYfr4NE899aUeScbbdLFI6u1XQudlJCPTxaISx5ZcwM+nP3v242ABcjgUcfCbz0AY547WazK4bWP3qicyxo4MoLOoe9WBq6EuG4CuZQrzKnq8ltSxud/6chdg8Mqp/IasEQ2TpvY78tEXDQ==</Modulus><Exponent>AQAB</Exponent><P>9ci4i5gUVSGo3PkIpTTXiNm7pCXTPlkDTxXzhxMlx8sgrh7auoLwMVOV0DQW1V84a3RXTwf/HalEKEY69TAYbmef0OqqHoGMHJStbjPaGdfNPdm5IOHp5qmIIHWOX2Z4nSyeEXY+z+GpYYvZvdKQIJ73SpVPM5U54s7phQIg6r0=</P><Q>3Cx9CQCr/THDyd5EY1OudeKa9tL5Vc8gXfzCJ2WO5s03sNjlwgVNAmudMFYpu7P+31onxBfpMUvRyL/2+E8mhOF8vXa8vaRYZiBaRZE+apoFbfLPsezmu37G4ff/sDnDm+aQSDU1kmCewnSsxRO7VDo8zkIGDo6nIdjhOEFvypE=</Q><DP>ML8ciuMgtTm1yg3CPzHZxZSZeJbf7K+uzlKmOBX+GkAZPS91ZiRuCvpu7hpGpQ77m6Q5ZL1LRdC6adpz+wkM72ix87d3AhHjfg+mzgKOsS1x0WCLLRBhWZQqIXXvRNCH/3RH7WKsVoKFG4mnJ9TJLQ8aMLqoOKzSDD/JZM3lRWk=</DP><DQ>PIZ+WNs2bIQhrnzLkAKRExcYQoH8yPoHi87QEMR6ZDhF9vepMY0DfobWz1LgZhk1F3FRPTbVhBezs9wRqHEZxa22/N6HRBrJsklyh21GG0f79h2put/FDgXr5nKmd2tpupHHWBJIh9THz+0DEao69QyNaqX7xESy7TsRrsVOVgE=</DQ><InverseQ>mlWr8mOkpY92UUO4ipPXx5IHv2xZfs4QDcUX1lTmDAvJg9oBw7KvQiHQqdTINLSaVi2hoMgzNZIAoWWLH3+I0cRwuHM7wLaD0pcVlxdpy99aid75Nmc83GuBkhwCJ6HVwayrLWr+UiCqLFik9mMrMYB5QPUptn+J9PRoxW7JRB4=</InverseQ><D>uLj7GJOALEnu+dALug8+5EnyIHQ4SeOAIrL05ny2rjBWS7X8X4wQ4QsE8bg+15wmQMR5ve08vgKkqSpv62kELL7VmpTIQamGp84w2DEb9p4idbxo5t1q0MQWhBfsjrb62bCuX0E7JaiJyKpJyEB+34I2sye2dvA9fLGDY9+6nxVkkspoBaPkqEvwShK9tNJaUQP6Ghl4h3MiDoyYnT+m+1BnrO7oTF1Ly636M5grEqrJcVzuVJOVzf31peC8Qhl+5qTXz2SE+WAUox5YhZDZcSI8iYPDkSxovNjNnLssad/a/dxermgoy7W/q3cJRrq+56YF1JCn1kCX/VhO7mq+gQ==</D></RSAKeyValue>"
        },
        "4": {
            "publicRSAKey": "<RSAKeyValue><Modulus>lCwdYrveozYYcKOSz4cjBfORvd6POZSxsM9JybWvTb9rr1qGhulgoNcMB0sUA4XnfNlt/aaT+JKSTEgynyX8of74Nmu70MRO2Nemi0YnI56gK2f0tIdmpFKnojgDTlLslQnKBzcK/elbcX2XE3FMK/hA2rkJBIMkIsXJ23nfWy/6KFB/nhXft+wzDahYmzaoLKsgq4xQInB6n0dUSkFNSMV+98CRjh+Y7pXlyEglDXxj+IhBVsl8s41c9vmgLHWS7feMufbeqko83fLv2GlI/aU0pvmYr9Lyf4kgPMp5aTqeyCm/ztb3bp5QoW7S2hlGP6gtxGr4s/lMpZN5YgTZbQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "privateRSAKey": "<RSAKeyValue><Modulus>yaxqjPJP5+Innfv5IdfQqY/ftS++lnDRe3EczNkIjESWXhHSOljEw9b9C+/BtF+fO9QZL7Z742y06eIdvsMPQKdGflB26+9OZ8AF4SpXDn3aVWGr8+9qpB7BELRZI/Ph2FlFL4cobCzMHunncW8zTfMId48+fgHkAzCjRl5rC6XT0Yge6+eKpXmF+hr0vGYWiTzqPzTABl44WZo3rw0yurZTzkrmRE4kR2VzkjY/rBnQAbFKKFUKsUozjCXvSag4l461wDkhmmyivpNkK5cAxuDbsmC39iqagMt9438fajLVvYOvpVs9ci5tiLcbBtfB4Rf/QVAkqtTm86Z0O3e7Dw==</Modulus><Exponent>AQAB</Exponent><P>/auFx84D7UlrfuFQcp5t+n2sex7Hj6kbK3cp27tZ2o6fix7GbJoG6IdBxRyE8NWVr+u5BnbT7wseDMEOjSbyxjuCl/vXlRX01JUhEPTC7bpIpGSU4XMngcE7BT2EEYtKdFQnPK9WW3k7sT2EC/rVIKu9YERyjDZico1AvC+MxUk=</P><Q>y4ahJvcD+6Wq2nbOnFUByVh79tIi1llM5RY/pVviE6IfEgnSfUf1qnqCs5iQn9ifiCDJjMqb+egXXBc/tGP/E5qGe8yTOEZ2Y5pu8T0sfkfBBNbEEFZORnOAFti1uD4nkxNwqolrJyFJGMmP7Ff533Su2VK79zbtyGVJEoAddZc=</Q><DP>FTcIHDq9l1XBmL3tRXi8h+uExlM/q2MgM5VmucrEbAPrke4D+Ec1drMBLCQDdkTWnPzg34qGlQJgA/8NYX61ZSDK/j0AvaY1cKX8OvfNaaZftuf2j5ha4H4xmnGXnwQAORRkp62eUk4kUOFtLrdOpcnXL7rpvZI6z4vCszpi0ok=</DP><DQ>p3lZEl8g/+oK9UneKfYpSi1tlGTGFevVwozUQpWhKta1CnraogycsnOtKWvZVi9C1xljwF7YioPY9QaMfTvroY3+K9DjM+OHd96UfB4Chsc0pW60V10te/t+403f+oPqvLO6ehop+kEBjUwPCkQ6cQ3q8xmJYpvofoYZ4wdZNnE=</DQ><InverseQ>cBvFa7+2fpF/WbodRb3EaGOe22C1NHFlvdkgNzb4vKWTiBGix60Mmab72iyInEdZvfirDgJoou67tMy+yrKxlvuZooELGg4uIM2oSkKWnf0ezCyovy+d62JqNGmSgESx1vNhm6JkNM8XUaKPb2qnxjaV5Mcsrd5Nxhg7p5q7JGM=</InverseQ><D>spmttur01t+SxDec11rgIPoYXMZOm76H1jFDFyrxhf9Lxz0zF5b7kpA3gzWuLwYr53kbYQTTzIG96g7k1sa6IEDDjiPGXYWNwxXsXw73EA9mpwybkqkpoPTXd+qvssZN8SKFweSJaNt3Xb05yVx4bATaL7+80Sztd+HABxag6Cs7eRBB63tLJFHJ+h4xznpOnOd476Sq+S0q64sMeYDLmP+2UiFA6PVhmO9Km0BRmOmzpV/cfLjY3BRfu0s7RFUPr4Sf/uxL8Kmia8rMHqNJfdUyjPVmjLsKLnCnnHlVrspxMOhhk8PFEy7ZbXpCxnum0vGMWPH1cJypE0cCWMACUQ==</D></RSAKeyValue>"
        },
        "5": {
            "publicRSAKey": "<RSAKeyValue><Modulus>15RBm/vARY0axYksImhsTicpv09OYfS4+wCvmE7psOvZhW2URZ2Rlf5DsEtuRG/7v5W/2obqqVkf+1dorPcR2iqrYZ4VVPf7KU3Cgqh0kzLGxWOpGxzwJULEyFVaiMDWbk7gr8rik/jYyhLiLc52zz3E3whTUPleKhOhXnxx1iOKY+TPVI8jJfDNiQoh0UvgjnkigJ/saPzjogeig/4McBc4l5cDkvttkKQKq7oXe9OCBClgKlYjcc1CNalwMlTz7NvLEko+ZLTgpA+kElZumyBXT67mmW7t7IDXorscAI7auwusKWmq797alFkQ/6sUqs8KKGnqQ2fwHfa/RYDhEw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "privateRSAKey": "<RSAKeyValue><Modulus>sJbFp3WcsiojjdQtVnTuvtawL2m4XxK93F6lCnFwcZqUP39txFGGlrogHMqreyawIUN7E5shtwGzigzjW8Ly5CryBJpXP3ehNTqJS7emb+9LlC19Oxa1eQuUQnatgcsd16DPH7kJ5JzN3vXnhvUyk4Qficdmm0uk7FRaNYFi7EJs4xyqFTrp3rDZ0dzBHumlIeK1om7FNt6Nyivgp+UybO7kl0NLFEeSlV4S+7ofitWQsO5xYqKAzSzz+KIRQcxJidGBlZ1JN/g5DPDpx/ztvOWYUlM7TYk6xN3focZpU0kBzAw/rn94yW9z8jpXfzk+MvWzVL/HAcPy4ySwkay0Nw==</Modulus><Exponent>AQAB</Exponent><P>19wQUISXtpnmCrEZfbyZ6IwOy8ZCVaVUtbTjVa8UyfNglzzJG3yzcXU3X35v5/HNCHaXbG2qcbQLThnHBA+obW3RDo+Q49V84Zh1fUNH0ONHHuC09kB//gHqzn/4nLf1aJ2O0NrMyrZNsZ0ZKUKQuVCqWjBOmTNUitcc8RpXZ8s=</P><Q>0W09POM/It7RoVGI+cfbbgSRmzFo9kzSp5lP7iZ81bnvUMabu2nv3OeGc3Pmdh1ZJFRw6iDM6VVbG0uz8g+f8+JT32XdqM7MJAmgfcYfTVBMiVnh330WNkeRrGWqQzB2f2Wr+0vJjU8CAAcOWDh0oNguJ1l1TSyKxqdL8FsA38U=</Q><DP>udt1AJ7psgOYmqQZ+rUlH6FYLAQsoWmVIk75XpE9KRUwmYdw8QXRy2LNpp9K4z7C9wKFJorWMsh+42Q2gzyoHHBtjEf4zPLIb8XBg3UmpKjMV73Kkiy/B4nHDr4I5YdO+iCPEy0RH4kQJFnLjEcQLT9TLgxh4G7d4B2PgdjYYTk=</DP><DQ>rdgiV2LETCvulBzcuYufqOn9/He9i4cl7p4jbathQQFBmSnkqGQ+Cn/eagQxsKaYEsJNoOxtbNu/7x6eVzeFLawYt38Vy0UuzFN5eC54WXNotTN5fk2VnKU4VYVnGrMmCobZhpbYzoZhQKiazby/g60wUtW9u7xXzqOdM/428Yk=</DQ><InverseQ>cGxDsdUW6B/B/nz9QgIhfnKrauCa8/SEVjzoHA6bdlLJNaw8Hlq2cW00ZcCGlXOXLCBBNl9Nn7rf00169TKFx2urNnEK52WKuOOPPDbDuEwAtuoarP8fx21TnF9d4E9ukmJ4ABx3oe8Y1ia/yoCCML3L4L6FbOpbu2vGi1L6zmo=</InverseQ><D>PMpalrBtVgQdoziUtvugKMA9fMT3PHt2MsO+Kx8sJ1+gg0952Sh7na3LWj4G1GlYHstdNj2kWJzUUsTnC/LLrPJ/yEfdmzKyo2FYXGGHgWcubH9QaiQCKv5qdormZhUnW9C3HOOVXUcBtCyRHKuSUqgcN1EWqIVc7CKJv3ugM1aEP5HF/IbDAmfKdllJd0tstKLP9AdA2v/5R+QpEFrG3QJ9TuY4tnGjLp80DEd0FwEk8cLKH5oO8RuLHudKdxJTwm7/jxgnwOuCVtmxcJigDlTPw0wO5oQyCg1YIVBWgRxGQRShofsGVZ3dRQVE+cNnUHgGaStWhETxrnzc6pLBqQ==</D></RSAKeyValue>",
        },
        "sign": {
            "publicRSAKey": "<RSAKeyValue><Modulus>xbbx2m1feHyrQ7jP+8mtDF/pyYLrJWKWAdEv3wZrOtjOZzeLGPzsmkcgncgoRhX4dT+1itSMR9j9m0/OwsH2UoF6U32LxCOQWQD1AMgIZjAkJeJvFTrtn8fMQ1701CkbaLTVIjRMlTw8kNXvNA/A9UatoiDmi4TFG6mrxTKZpIcTInvPEpkK2A7Qsp1E4skFK8jmysy7uRhMaYHtPTsBvxP0zn3lhKB3W+HTqpneewXWHjCDfL7Nbby91jbz5EKPZXWLuhXIvR1Cu4tiruorwXJxmXaP1HQZonytECNU/UOzP6GNLdq0eFDE4b04Wjp396551G99YiFP2nqHVJ5OMQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "privateRSAKey": "<RSAKeyValue><Modulus>xbbx2m1feHyrQ7jP+8mtDF/pyYLrJWKWAdEv3wZrOtjOZzeLGPzsmkcgncgoRhX4dT+1itSMR9j9m0/OwsH2UoF6U32LxCOQWQD1AMgIZjAkJeJvFTrtn8fMQ1701CkbaLTVIjRMlTw8kNXvNA/A9UatoiDmi4TFG6mrxTKZpIcTInvPEpkK2A7Qsp1E4skFK8jmysy7uRhMaYHtPTsBvxP0zn3lhKB3W+HTqpneewXWHjCDfL7Nbby91jbz5EKPZXWLuhXIvR1Cu4tiruorwXJxmXaP1HQZonytECNU/UOzP6GNLdq0eFDE4b04Wjp396551G99YiFP2nqHVJ5OMQ==</Modulus><Exponent>AQAB</Exponent><P>8tHjikSSZN18ggXxm3MGJV8Nnb1tP3onQJZcZXOnzHptK7knmOWzuw/wMRyMZnq8ewsY6+Rw3HNydHeX/kc7PpMi69W5SbfpvWMeW2rXFlK2MZ4pmzWKGElK7aUgD5OsrwUJGcoBEnS6CFcY1kUi2B4zbfRKCOnZEvghJcnvbhc=</P><Q>0HJLZHA2lRi+QJJkdIWdAz+OrWOV3HD7SniMAalYuKURoD/zFZSdmucKs8UX+32WWlt1NH90Ijye0gwDLZ0fghQfJgpRqHIdLMIBQ0qlLSzjfeSfmHL20a+fuPK44nh2T0WjU8hkzup/OaR0IFtfc0XZManM69tgYkccLeyxWvc=</Q><DP>0ckOik32INjOklNqS0BURgNaczbOZTI3KXD+wNPsXBhFq6nbERkbb/k0LmoYzw0pPDD5Rgxmib/gWcldct29zLE4UYKkA5G2it5QwvCKhYnOSQ35qlPWTGc+KhUonuyaG9gA5dwFkxlwBHajSbQPh6KIEm4lbJAE8IOZt9lAV98=</DP><DQ>qlyvh7A6vBLT87xyA9XsJOp+NvIMWnWwvAXYD8eTrp2i0UFS8FFdmmu4kILGfhH/n2veWADPLugyueN9eXtQdCTz7EhEwxI5DAqns5K/ezOT3qHLWnKjjW8ncKZYOyhPMazttx0yXvbC8p6ZFpT3ZyQwRmnMBPxwQwJxYotvzLM=</DQ><InverseQ>MibG8IyHSo7CJz82+7UHm98jNOlg6s73CEjp0W/+FL45Ka7MF/lpxtR3eSmxltvwvjQoti3V4Qboqtc2IPCt+EtapTM7Wo41wlLCWCNx4u25pZPH/c8g1yQ+OvH+xOYG+SeO98Phw/8d3IRfR83aqisQHv5upo2Rozzo0Kh3OsE=</InverseQ><D>xHmGYY8qvmr1LnkrhYTmiFOP2YZV8nLDqs6cCb8xM+tbQUr62TwOS0m/acwL6YnPu4Qx/eI1/PfvHTXzu6pQA7FTRECQcbr9qNTAo6QkZJgWc+dOiARlOtCrdY+ZMHQhHq4E1tat++c+MJfH+y5ki9lOlrynHaI01caIQZCFCe7IbZprpA4tmJzH3uk/9iblwwy/K7yHJ36+RDAoD0LPsS3ixBqyCXaVMtYiGGWK8766ScH/RCS9w9Hu45KW7wEGfBBfWIRIsyYTpnc06luD4FtslGh2Hd6uUI4iC8uwAvqDmKE2ZZ90X4zzsZfm2I3jDlpapILaT0JABOCOuMPEWQ==</D></RSAKeyValue>"
        }
    }

    public_key_xml = keys[sign_key_type]['publicRSAKey']
    private_key_xml = keys[key_type]['privateRSAKey']
    
    pub_rsa_key = get_pub_key_from_xml(public_key_xml)
    priv_rsa_key = get_priv_key_from_xml(private_key_xml)

    try:
        content = base64.b64decode(server_response['content'])
        sign = base64.b64decode(server_response['sign'])

    except Exception:
        print(f'\nAn error occured while parsing the input data: \n\n{traceback.format_exc()}')

    if content:
        dec = PKCS1_v1_5.new(priv_rsa_key)

        chunk_size = 256

        out = b''

        for i in range(0, len(content), chunk_size):
            chunk = content[i:i + chunk_size]
            out += dec.decrypt(chunk, None)


        output_filename = input("Enter the output file name (leave it blank if you don't want to save to a file): ")

        if output_filename:
            with open(output_filename, 'wb') as out_fp:
                out_fp.write(out)

        #calc_sign = do_sign(out, signing_priv_key)#
        #print("\nReceived sign: {}\n".format(base64.b64encode(sign).decode()))
        #print("Calculated sign: {}\n".format(base64.b64encode(calc_sign).decode()))

        print("\nContent: \n\n{}\n".format(base64.b64encode(out).decode()))

        if input("Do you want to skip the signature check (y or n): ") == "n":
            verify(out, sign, pub_rsa_key)
