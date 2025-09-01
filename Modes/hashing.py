import os
import hashlib as hl
import hmac as hm

#Hashing
def GetHashText(text):

    '''

        Función que permite obtener el hash SHA-256 de un texto

        Params:
            text: El texto del mensaje del cual se calculará el hash

        Returns:
            hash: El hash calculado para dicho texto
    '''

    return hl.sha256(text.encode()).hexdigest()

def GetHashFile(filepath):

    '''
    
        Función para calcular el hash SHA-256 de un archivo

        Params:
            filepath: Ruta del archivo como string
        
        returns:
            hash: El hash calculado para el archivo
            >e: Error si la apertura del archivo es fallida
    
    '''

    hasher = hl.sha256()
    try:
        with open (filepath, 'rb') as file:
            while chunk := file.read(4096):
                hasher.update(chunk)
            return hasher.hexdigest()
        
    except Exception as e:
        return e
    
def GenHmac(text, key):

    '''

        Función para crear un nuevo objeto HMAC para verificación de mensajes

        Params:
            text: El mensaje para generar el HMAC
            key: Llave aleatoria para la encriptación
        
        Returns:
            hmac: Objeto HMAC para posterior verificación del mensaje
    
    '''

    return hm.new(key, text.encode(), hl.sha256).hexdigest()

def VerifyHmac(text, key, hmac):

    '''

        Función para la verificación de un texto según su llave y HMAC

        Params:
            text: El mensaje a ser verificado
            key: La llave con la que se generó el HMAC
            hmac: El hmac único asociado al mensaje
        
        Returns:
            bool: Bandera que describe el estado de verificación del texto
            >False: El texto no es el mismo con el que se generó el HMAC

            >True: El texto es el mismo con el que se generó el HMAC

    '''

    newHmac = GenHmac(text, key)
    return hm.compare_digest(newHmac, hmac)

def GenKey():

    '''
    
        Función que retorna una secuencia de bytes aleatoria según el tamaño (16 bytes)

        Returns:
            bytes: Secuencia de 16 bytes aleatoria

    '''

    return os.urandom(16)

#Auth

def SaltPassword(password, salt):

    '''

        Funcion que permite la generación de un hash SHA-256 con sal aleatoria

        Params:
            password: La contraseña que el usuario entró al registrarse
            salt: Secuencia de bytes aleatoria para modificar el resultado del hash de manera impredecible

        Returns:
            tuple:
                >passHash: El hash del password mas la sal

                > salt: La secuencia de bytes aleatoria. Si no existe, se genera en tiempo de ejecución
    
    '''

    if salt is None:
        salt = GenKey()

    passHash = hl.sha256(salt + password.encode()).hexdigest()
    return passHash, salt

def CompareSaltedHash(typedPass, storedHash, storedSalt):

    '''
    
        Función que permite la comparación del hash guardado con el hash calculado en tiempo de ejecución según la sal almacenada

        Params:
            typedPass: La contraseña ingresada por el usuario en el momento de iniciar sesión
            storedHash: El hash que se generó cuando se asigno la contraseña para comparación guardada en archivo
            storedSalt: La secuencia de bytes guardada en archivo 

        Returns:
            bool: Bandera que indica el estado de la comprobación
                >False: El hash calculado con la contraseña entrada no concuerda con el hash generado en el registro, por lo cual
                la contraseña no concuerda

                >True: El hash calculado con la contraseña entrada concuerda y se evalúa como correcta

    
    '''

    newHash, _ = SaltPassword(typedPass, storedSalt)
    
    return hm.compare_digest(newHash, storedHash)

class user:

    '''
    
        Clase que define a un usuario (por conveniencia para este ejercicio)

        Attributes:
            name: El nombre de usuario que eligió
            hash: El hash generado al momento de escoger la contraseña
            salt: La secuencia de bytes aleatoria usada para generar el hash
    
    '''

    def __init__(self, name, hash, salt):

        '''
        
            Constructor con parámetros de la clase
        
        '''
    
        self.name = name
        self.hash = hash
        self.salt = salt

    def __str__(self):

        '''
        
            Función que permite el retorno del objeto como un string legible

            Returns:
                string: El objeto en texto legible como: Nombre, Hash, Sal
        
        '''

        return f"{self.name}, {self.hash}, {self.salt}"

    #Setters y Getters
    def SetName(self, name):
        self.name = name

    def SetHash(self, hash):
        self.hash = hash

    def SetSalt(self, salt):
        self.salt = salt

    def GetName(self):
        return self.name

    def GetHash(self):
        return self.hash

    def GetSalt(self):
        return self.salt  

