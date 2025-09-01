def encrypt(text, shift):

    '''
    
        Función que permite la encripción de un mensaje de texto con un desplazamiento determinado.

        Params:
            text: El texto a ser cifrado
            shift: Numero entero que representa el desplazamiento de la cifra
        Returns:
            result: String que contiene el mensaje cifrado según el desplazamiento
    '''
    
    result = ""

    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char

    return result

def decrypt(text, shift):

    '''

        Función que permite descifrar un texto con cifra Cesar

        Params:
            text: El texto encriptado
            shift: El desplazamiento con el que se cifró el mensaje

        Returns:
            result: String que contiene el texto original
    
    '''

    return (encrypt(text, -shift))

def bruteforce(text):

    '''
    
        Función que permite atacar la cifra, mostrando todas las combinaciones posibles según
        el desplazamiento máximo permitido por la cifra.

        Params:
            text: El texto cifrado que se quiere atacar
        
        Returns:
            result: Lista de todas los posibles strings que pueden ser generados por cifra Cesar
    
    '''

    result = []
    for shift in range(26):
        result.append(decrypt(text,shift))
    
    return result
