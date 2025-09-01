from cryptography.fernet import Fernet as fn

def GenKey():

    '''
    
        Función que permite generar una llave aleatoria para la encriptación

        Returns:
            key: Llave aleatoria en bytes
    
    '''

    key = fn.generate_key()

    return key

def Encrypt(text, key):

    '''

        Función que permite encriptar texto usando una llave aleatoria

        Params:
            text: El mensaje que va a ser encriptado
            key: Llave que será usada para la encriptación
        
        Returns:
            token: Mensaje encriptado en bytes        
    
    '''

    cipher = fn(key)
    token = cipher.encrypt(text)

    return token

def Decrypt(token, key):

    '''
    
        Función que permite descifrar un mensaje a partir de un token y la llave con la que se encriptó

        Params:
            token: Mensaje encriptado en bytes
            key: Llave con la que se encriptó el mensaje

        Returns:
            text: El mensaje original en texto legible
    
    '''

    cipher = fn(key)
    text = cipher.decrypt(token)

    return text

    