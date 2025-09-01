from cryptography.hazmat.primitives.asymmetric import rsa as rs, padding as pd
from cryptography.hazmat.primitives import hashes as ha
from cryptography.hazmat.primitives import serialization as se



def GenKey():

    '''
    
        Función que genera una llave privada según un exponente público y un tamaño.
        El exponente público suele ser un número de Fermat, el cual también debe ser primo para mayor robustez
        El tamaño se define como un múltiple de 8 segun 2 a la n que coincide con tamaños comúnes de multiplos de bytes

        Returns:
            private_key: La llave privada generada por RSA
    
    '''

    private_key = rs.generate_private_key(65537, 2048)    

    return (private_key)


def SaveKey(key, keyName): 

    '''

        Función que permite la escritura de la llave privada según la codificación PEM 

        Params:
            key: La llave a ser guardada
            keyName: El nombre del archivo en el que se guardará la llave
        
        Returns:
            success: Bandera que describe el éxito de la operación de escritura
                >False: La llave no pudo ser guardada en el archivo

                >True: La llave fue guardada en el archivo con éxito
    
    '''

    success = False
    pem = key.private_bytes(encoding = se.Encoding.PEM, format = se.PrivateFormat.TraditionalOpenSSL, encryption_algorithm = se.NoEncryption())
    try:
        with open (keyName, 'wb') as file:

            file.write(pem)
        success = True
        return success
    
    except Exception:
        return success

def SavePublic(key, keyName):

    '''

        Función que permite guardar la llave pública como un archivo de texto según la codificación PEM

        Params:
            key: La llave a ser guardada
            keyName: El nombre del archivo en el que se guardará la llave

        Returns:
            success: Bandera que describe el éxito de la operación de escritura
                >False: La llave no pudo ser guardada en el archivo

                >True: La llave fue guardada en el archivo con éxito

    '''

    success = False
    pem = key.public_bytes(encoding = se.Encoding.PEM, format = se.PublicFormat.SubjectPublicKeyInfo)

    try:
        with open(keyName, 'wb') as file:
            
            file.write(pem)
        success = True
        return success
    
    except Exception:
        return success

def SaveSignature(filename, signature):

    '''

        Función que permite guardar la firma digital (por conveniencia para este ejercicio) en un archivo de texto

        Params:
            filename: El nombre del archivo en el que se guardará la firma
            signature: Los datos de la firma digital

        Returns:
            bool: Bandera que describe el éxito de la operación de escritura
                >False: La llave no pudo ser guardada en el archivo

                >True: La llave fue guardada en el archivo con éxito
    
    '''

    try:

        with open (filename, 'w') as file:
            file.write(signature)
        return True
    
    except Exception as e:

        print(f"Error al guardar firma: {e}")

        return False

def LoadKey(fileName):

    '''

        Funcion que permite cargar la llave privada desde un archivo

        Params:
            fileName: Nombre del archivo del cual se cargará la llave
        
        Returns:
            privKey: Llave privada decodificada para su uso
    
    '''

    with open (fileName, 'rb') as key:
        pemlines = key.read()
    privKey = se.load_pem_private_key(pemlines, None)
    return privKey

def LoadPublic(filename):

    '''

        Funcion que permite cargar la llave pública desde un archivo

        Params:
            fileName: Nombre del archivo del cual se cargará la llave
        
        Returns:
            pubKey: Llave pública decodificada para su uso
    
    '''

    with open(filename, 'rb') as key:
        pemlines = key.read()
    pubKey = se.load_pem_public_key(pemlines)
    return pubKey
    
def LoadSignature(filename):

    '''

        Funcion que permite cargar la firma digital desde un archivo

        Params:
            fileName: Nombre del archivo del cual se cargará la firma
        
        Returns:
            privKey: Firma digital

    '''

    with open(filename) as file:
        signature = file.read()
    return signature

def Sign(message, private_key:rs.RSAPrivateKey):

    '''
    
        Función que permite firmar texto con la llave privada

        Params:
            message: El mensaje a firmar
            private_key: La llave privada con la que se firmará el mensaje

        Returns:
            signature: La firma digital como texto plano en formato hexadecimal
    
    '''

    message = message.encode()
    signature = private_key.sign(message, pd.PSS(pd.MGF1(ha.SHA256()), pd.PSS.MAX_LENGTH), ha.SHA256())
    return signature.hex()

def Verify(message, signature, pub_key:rs.RSAPublicKey):

    '''
    
        Función que permite verificar la firma digital de un mensaje según su llave pública
        
        Params:
            message: El mensaje al que se le verificará la firma
            signature: La firma digital asociada al mensaje
            pub_key: La llave pública relacionada con la llave privada con la cual se firmó el mensaje

        return:
            bool: Bandera que describe el estado de la verificación de la firma
            >False: La verificación falló por lo tanto el mensaje no es legítimo o se modificó

            >True: Se completó la verificación con éxito, por lo tanto el mensaje es legítimo
    
    '''

    try:

        pub_key.verify(signature, message, pd.PSS(pd.MGF1(ha.SHA256()), pd.PSS.MAX_LENGTH), ha.SHA256())

        return True
    
    except Exception as e:
        print(f"Error verificando por: {e}")
        return False