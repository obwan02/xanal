#!/usr/bin/env python3

def encrypt(data, password):
    output = bytearray(len(data))
    for i in range(len(data)):
        password_index = i % len(password)
        output[i] = data[i] ^ password[password_index]

    return output

if __name__ == "__main__":
    file_name = input("File Path to Encrypt: ")
    xor_password = input("Input Password: ")
    output_path = input("Output Path: ")

    with open(file_name, 'rb') as file:
        data = file.read()
        output = encrypt(data, xor_password.encode("utf-8"))

    with open(output_path, 'wb') as file:
        file.write(output)
