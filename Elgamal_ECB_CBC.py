#!/usr/bin/env python3
import random
from math import pow
import os


#Encryption function which multiplies message (int) with g^(ab).
def encrypted_elgamal(message, g_power_ab):
    return (g_power_ab * message)

#Decryption function which divides encrypted message with g^(ab).
def decrypted_elgamal(encrypted_message, g_power_ab):
    return (encrypted_message // g_power_ab)


#Modulo function for the numbers which has power.
def power(base, power, mod):
    x = 1
    y = base

    while power > 0:
        if power % 2 != 0:
            x = (x * y) % mod
        y = (y * y) % mod
        power = int(power / 2)
    return x % mod


#Encryption function for ECB ciphering mode. It converts string char message to int and encrypts to ciphertext.
def ECB_encrypt(message, g_power_ab):

    cipher_text = []
    for i in range(0, len(message)):
        cipher_text.append(message[i])

    #array for ciphertext
    for i in range(0, len(cipher_text)):
        cipher_text[i] = encrypted_elgamal(ord(cipher_text[i]), g_power_ab)  #plaintext to ciphertext
    return cipher_text

#Decryption function for ECB ciphering mode. It decrypts ciphertext to int and converts to char text. (plaintext)
def ECB_decrypt(encrypted_message, key):

    decrypted_message = []
    #array for plaintext
    for i in range(0, len(encrypted_message)):
        decrypted_message.append(chr(decrypted_elgamal(encrypted_message[i], key))) #ciphertext to plaintext

    return decrypted_message

#Encryption function for CBC ciphering mode. It makes XOR operation between first item of message and initialization vector.
#After, It encrypts the item and next item will be result of opeartion which is XOR between encrypted item and the next item of the list.
def CBC_encrypt(plain_text, key, iv):

    c = []
    for i in range(0, len(plain_text)):
        c.append(ord(plain_text[i])) #character to integer

    c[0] = c[0] ^ iv # XOR'ing with initialization vector

    for i in range(0, (len(c) - 1)):
        c[i] = encrypted_elgamal(c[i], key)
        c[i+1] = c[i+1] ^ c[i]

    c[len(c) - 1] = encrypted_elgamal(c[len(c) - 1], key)
    return c

#Decryption function for CBC ciphering mode. It makes the opposite operation of CBC_encrpyt function to get plaintext message.
def CBC_decrypt(cipher_text, key, iv):

    decrypted_message = []
    plain_text = []

    for i in range(0, len(cipher_text)):
        decrypted_message.append(decrypted_elgamal(cipher_text[i], key))

    plain_text.append(chr(iv ^ decrypted_message[0])) # XOR'ing with initialization vector
    
    for i in range(1, len(cipher_text)):
        plain_text.append(chr(cipher_text[i-1] ^ decrypted_message[i]))

    return plain_text

#Function for calculating gcd.
def gcd(a, b):

    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)


#Function for checking whether number is prime or not.
def check_prime(number):
    control = False
    for i in range(2,number):
        if number % i == 0:
            control = False
            break
        else:
            control = True

    return control

#Function for creating generator.
def generator(field):
    while(True):
        results_mod = [] #array of possible generator ^ x (mod field) x={1,2,3...}
        possible_generator = random.randint(2,field)

        for i in range(1,field):
            results_mod.append(power(possible_generator,i,field))

        #checking if there is same numbers inside the array. If it not, then this is our generator.
        if(len(results_mod) == len(set(results_mod))):
            break
    return possible_generator

    
#Function for generating key.
def gen_key(p):
    key = random.randint(pow(10, 2), p)

    #checking gcd
    while gcd(p, key) != 1:
        key = random.randint(pow(10, 2), p)
    
    return key


def main():

    #output .txt file for the testing.
    output_file = open("output_text.txt",'w')

    #choosing prime number between 10^2-10^5.
    p = random.randint(pow(10, 2), pow(10, 5))
    while(True):
        if check_prime(p) == True:
            break
        else:
            p = random.randint(pow(10, 2), pow(10, 5))
    
    #choosing generator in the field p.
    g = generator(p)
    print("\nIn the field: ", p, "\nwe found a the generator: ", g)
    output_file.write("In the field: "+ str(p)+ "\nwe found a the generator: "+ str(g))
    
    rec_key = gen_key(p) # Public key
    g_power_a = power(g, rec_key, p)

    print("the public key: ", rec_key)
    output_file.write("\nthe public key: "+ str(rec_key))

    print("g to the power of a: ", g_power_a)
    output_file.write("\ng to the power of a: "+ str(g_power_a))

    send_key = gen_key(p)# Private key
    g_power_b = power(g, send_key, p)  

    print("the private key: ", send_key)
    output_file.write("\nthe private key: "+ str(send_key))

    print("g to the power b: ", g_power_b)
    output_file.write("\ng to the power b: "+ str(g_power_b))


    g_power_ab = power(g_power_a, send_key, p)
    print("g to the power of ab:", g_power_ab, "\n")
    output_file.write("\ng to the power of ab:"+ str(g_power_ab)+ "\n")

    while(True):

        print("Please choose input type:\n1 Keyboard Input\n2 File Input (input.txt)\n3 Exit program")
        input_type = input() #FIRST INPUT FOR THE PROGRAM: choosing input type.

        if input_type == "1":

            print("\nPlease enter a string to be encrypted: ")
            message = input() #SECOND INPUT FOR THE PROGRAM: plaintext message.
            output_file.write("\nPlaintext message is: "+message+"\n")

        elif input_type == "2":

            input_file = open("input_test.txt",'r') #open input test file to read.
            message = input_file.read().splitlines()
            count = 1
            
            #getting plaintext messages line by line in input test file.
            for msg in message:
                print("\nMessage " ,str(count)," in input.txt file: ",msg)
                output_file.write("\nPlaintext message "+str(count) +" is: "+msg)
                count +=1
                
            input_file.close()

        elif input_type == "3":
            break

        else:
            print("\nPlease enter valid number.")
            continue


        print("\nPlease choose a ciphering mode:\n1 ECB\n2 CBC\n3 Exit program")
        cipher_mode = input() #THIRD INPUT OF THE PROGRAM: choosing the ciphering mode.

        if cipher_mode == "1":

        # # ECB
            #encryption of the message.
            print("\nWe used ECB cipher mode to break up the message, into smaller parts, and encrypt every part individually")
            output_file.write("\n\nWe used ECB cipher mode to break up the message, into smaller parts, and encrypt every part individually\n")

            
            for msg in message:
                #checking if message is string or list. If it is string, then it means it is keyboard input, if it is list, then it is .txt file input.
                if type(message) == str:
                    msg = message
                
                cipher_text = ECB_encrypt(msg, g_power_ab)

                print("\nThis is our encrypted message: ", cipher_text)
                output_file.write("\nThis is our encrypted message: "+ str(cipher_text))

                #decryption of the message.
                plain_text = ECB_decrypt(cipher_text, g_power_ab)
                dmsg = ''.join(plain_text)

                print("This is our decrypted message: ", dmsg)
                output_file.write("\nThis is our decrypted message: "+ dmsg+"\n")

                if msg == message:
                    break

            break

        elif cipher_mode == '2':

        # # CBC
            #declaring initialization vector as random. 
            iv = random.randint(1, 2000000)

            #encryption of the message.
            print("\nWe used CBC cipher mode to break up the message, into smaller parts, and encrypt every part individually")
            output_file.write("\n\nWe used CBC cipher mode to break up the message, into smaller parts, and encrypt every part individually\n")
            
            #checking if message is string or list. If it is string, then it means it is keyboard input, if it is list, then it is .txt file input.
            for msg in message:
                if type(message) == str:
                    msg= message
                
                cipher_text = CBC_encrypt(msg, g_power_ab, iv)

                print("\nThis is our encrypted message: ", cipher_text)
                output_file.write("\nThis is our encrypted message: "+ str(cipher_text))

                #decryption of the message.
                plain_text = CBC_decrypt(cipher_text, g_power_ab, iv)
                dmsg = ''.join(plain_text)

                print("This is our decrypted message: ",dmsg)
                output_file.write("\nThis is our decrypted message: "+dmsg+"\n")

                if msg == message:
                    break
            break

        elif cipher_mode == '3':
            break
        else:
            print("Please enter 1 or 2 to choose a ciphering mode.\n")
    output_file.close()           

if __name__ == "__main__":
    main()