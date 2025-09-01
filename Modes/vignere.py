def encrypt(text, key):

    '''

        Función que permite encriptar un texto según la cifra de Vignère

        Params:
            text: El texto a encriptar
            key: La lave de Vignere que se entró por el usuario
        
        Returns:
            LiteralString: Un string literal que representa el texto cifrado
    
    '''

    result = []
    key = key.lower()
    key_idx = 0

    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            pos = ord(key[key_idx % len(key)]) - 97
            result.append(chr((ord(char) - offset + pos) % 26 + offset))
            key_idx += 1
        
        else:
            result.append(char)
    
    return "".join(result)

def decrypt(text, key):

    ''''
    
        Función que permite descifrar un texto según la llave Vignere que se utilizo para cifrarlo

        Params:
            text: El texto cifrado
            key: La llave Vignere que se utilizó para cifrar el mensaje
        
        Returns:
            LiteralString: El mensaje original descifrado 

    '''

    result = []
    key.lower()
    key_idx = 0
    
    for char in text:
        if char.isalpha():

            offset = 65 if char.isupper() else 97
            pos = ord(key[key_idx % len(key)]) - 97
            result.append(chr((ord(char) - offset - pos) % 26 + offset))
            key_idx += 1

        else:
            result.append(char)
    
    return "".join(result)
