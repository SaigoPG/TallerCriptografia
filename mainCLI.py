#Ejercicios del Taller de Criptografía - Seguridad Informática 2025-2
#Realizado por Juan Pardo y Santiago Ramírez

import ast                          #Librería importada para convertir un string hexdigest guardado en un archivo de vuelta a un objeto de bytes
import easygui as eg                #Librería de interfaz de usuario simple, para los puntos donde se creyó que era absolutamente necesario (por tiempo)

#Modes: Directorio donde se encuentran las librerias que realizamos para este taller
from Modes import caesar as cs      #Contiene los métodos asociados a la cifra cesar
from Modes import chain as bc       #Contiene la definición de los objetos necesarios para el ejemplo de blockchain y sus correspondientes métodos
from Modes import digsign as ds     #Contiene los métodos necesarios para la creación de una firma digital y su verificación, guardando las claves como archivos
from Modes import fernet as fn      #Contiene los métodos asociados a la encriptación Fernet/AES
from Modes import hashing as hs     #Contiene los métodos necesarios para los ejercicios de hashing, hmac y autenticación con hash y sal
from Modes import vignere as vg     #Contiene los métodos asociados a la cifra de Vignere
from Modes import https as sw       #Contiene los métodos para la demostración de certificación web


def CheckInt(incoming_value):

    '''
        Verifica que un string de entrada tenga posibilidad de convertirse
        en un entero. Previene que el usuario ingrese caracteres inválidos
        cuando la entrada es necesaria.

            Params: 
                incoming_value: String a evaluar

    '''

    try:
        incoming_value = int(incoming_value)
        return True
    
    except ValueError:
        return False

def MainMenu():

    '''

        Menú principal de la aplicación

    '''

    while True:

        print("Selecciona la seccion a revisar:")
        print("1. Criptografia clasica")
        print("2. Hashes y HMAC")
        print("3. Autenticacion con Hash y Sal")
        print("4. Firma Digital") 
        print("5. Blockchain") 
        print("6. Ejercicio HTTPS")
        print("7. Salir")
        choice = input("Opcion(numero): ")

        if (CheckInt(choice)):

            choice = int(choice)

            match choice:
                case 1:
                    CryptMenu()
                case 2:
                    HashMenu()
                case 3:
                    AuthMenu()
                case 4:
                    SignMenu()
                case 5:
                    BlockMenu()
                case 6:
                    WebMenu()
                case 7:
                    print("Saliendo...")
                    break
                case _:
                    print("Selecciona un numero valido")

        else:
            print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

#Cryptography
def CryptMenu():

    '''
    
        Menú de selección del método criptográfico que se desea utilizar para
        cifrar un texto.
    
    '''

    print("Selecciona el tipo de cifra a usar:")
    print("1. Cifra Cesar")
    print("2. Cifra Vignere")
    print("3. Cifra Fernet")
    print("4. Volver")

    choice = input("Opcion(numero): ")

    if (CheckInt(choice)):

        choice = int(choice)

        match choice:
            case 1:
                CaesarMenu()
            case 2:
                VignereMenu()
            case 3:
                FernetMenu()
            case 4:
                print("Volviendo al menu principal")
                return
            case _:
                print("Selecciona una opcion valida")

    else:
        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

def CaesarMenu():

    '''
    
        Submenú que contiene las opciones relacionadas a la cifra Cesar.

    '''

    print("Selecciona la accion que deseas realizar con cifra Cesar")
    print("1. Encriptar")
    print("2. Desencriptar")
    print("3. Ataque de fuerza bruta")
    print("4. Volver")

    choice = input("Opcion(numero): ")

    if (CheckInt(choice)):

        choice = int(choice)

        match choice:
            case 1:

                workString = input("Ingresa el texto que deseas encriptar: ")

                while True:
                    shift = input("Ingresa el valor del desplazamiento para el cifrado: ")

                    if(CheckInt(shift)):
                        break
                    else:
                        print("El desplazamiento debe ser un numero entero!")

                workString = cs.encrypt(workString, int(shift))
                print(f"El texto encriptado con desplazamiento de {shift} es: {workString}")

            case 2:
                
                workString = input("Ingresa el texto que deseas desencriptar: ")

                while True:
                    shift = input("Ingresa el valor del desplazamiento para el descifrado: ")

                    if(CheckInt(shift)):
                        break
                    else:
                        print("El desplazamiento debe ser un numero entero!")
                
                workString = cs.decrypt(workString, int(shift))
                print(f"El texto desencriptado con desplazamiento de {shift} es: {workString}")

            case 3:
                
                workString = input("Ingresa el texto encriptado que deseas atacar: ")

                possibilities = cs.bruteforce(workString)
                print("Las posibles cadenas desencriptadas son las siguientes: ")

                for counter in range(len(possibilities)):
                    print(f"{counter}. {possibilities[counter]}")

            case 4:
                print("Volviendo al menu principal")
                return
            case _:
                print("Selecciona una opcion valida")

    
    else:
        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

def VignereMenu():

    '''
    
        Submenú que contiene las opciones relacionadas a la cifra Vignere.

    '''

    print("Selecciona la accion que deseas realizar con la cifra de Vignere: ")
    print("1. Encriptar")
    print("2. Desencriptar")
    print("3. Volver")

    choice = input("Opcion(numero): ")

    if(CheckInt(choice)):

        choice = int(choice)

        match choice:
            case 1:

                workString = input("Ingresa el texto que deseas encriptar: ")
                key = input("Ingresa la llave de encripcion deseada: ")

                workString = vg.encrypt(workString, key)

                print(f"El texto encriptado con la llave {key} es: {workString}")

            case 2:

                workString = input("Ingresa el texto encriptado que deseas descifrar: ")
                key = input("Ingresa la llave de encripcion utilizada para cifrar el texto: ")

                workString = vg.decrypt(workString, key)

                print(f"El texto descifrado con la llave {key} es: {workString}")

            case 3:
                print("Volviendo al menu principal")
                return
            case _:
                print("Selecciona una opcion valida")

    else:
        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

def FernetMenu():

    '''
    
        Submenú que contiene las opciones relacionadas a la cifra Fernet.

    '''

    print("Selecciona la accion que quieres realizar con la cifra Fernet:")
    print("1. Encriptar")
    print("2. Desencriptar")
    print("3. Volver")

    choice = input("Opcion(numero): ")

    if(CheckInt(choice)):

        choice = int(choice)

        match choice:

            case 1:

                print("Generando llave:")
                key = fn.GenKey()                

                key_fileName = input("La llave sera guardada como un archivo, ingrese el nombre que desea para el mismo: ")

                with open(key_fileName, 'wb') as file:
                    
                    file.write(key)
                    
                print("Llave guardada en la carpeta local")
                
                workString = input("Ingrese el texto a encriptar: ")
                workString = workString.encode("utf-8")

                workString = fn.Encrypt(workString, key)

                print(f"El texto encriptado con cifra Fernet es: {workString}")



            case 2:

                workString = input("Ingrese el mensaje encriptado: ")
                key_name = input("Ingrese el nombre de la llave generada al encriptar: ")
                try:

                    with open (key_name, "rb") as file:
                        key = file.read()
                    print("Llave cargada")

                    workString = fn.Decrypt(workString, key)

                    print(f"El mensaje desencriptado es: {workString}")

                except Exception as e:
                    print(f"La llave no pudo cargarse, error: {e}")
                    return
                

            case 3:
                print("Volviendo al menu principal")
                return
            case _:
                print("Selecciona una opcion valida")
    
    else:
        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

#Hashes
def HashMenu():

    '''
    
        Menú que contiene las opciones relacionadas a hashing, comparación de hashes
        y HMAC.

    '''

    print("Selecciona una opcion: ")
    print("1. Ver Hash SHA-256 de un texto")
    print("2. Ver hash SHA-256 de un archivo")
    print("3. Comparar hash SHA-256")
    print("4. Generar HMAC")
    print("5. Volver")

    choice = input("Opcion(numero): ")

    if (CheckInt(choice)):
        choice = int(choice)

        match choice:
            case 1:

                SeeHashText()

            case 2:

                SeeHashFile()

            case 3:
                
                CompareHash()

            case 4:
                HmacStuff()
            case 5:
                print(choice)
                return
            case _:
                print("Selecciona un numero valido")

    else:
            print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")   

def SeeHashText():

    '''
    
        Submenú que permite la comprobación del hash SHA-256 de un texto

    '''

    workingString = input("Ingresa el texto al que quieres comprobar el hash SHA-256: ")
    sha_hash = hs.GetHashText(workingString)
    print(f"El hash SHA-256 del texto es: {sha_hash}")

def SeeHashFile():

    '''
    
        Submenú que permite la comprobación del hash SHA-256 de un archivo (Utiliza easygui
        para la selección del mismo)

    '''

    filepath = eg.fileopenbox("Selecciona un archivo", "Hash SHA-256 para archivos")
    sha_hash = hs.GetHashFile(filepath)
    print(f"El hash del archivo es: {sha_hash}")

def CompareHash():

    '''
    
        Submenú que permite la comparación del hash de dos archivos (También utiliza easygui)

    '''

    filepath_A = eg.fileopenbox("Selecciona el primer archivo", "Comparacion de hash SHA-256")
    filepath_B = eg.fileopenbox("Selecciona el segundo archivo", "Comparacion de hash SHA-256")

    hash_A = hs.GetHashFile(filepath_A)
    hash_B = hs.GetHashFile(filepath_B)

    if(hash_A == hash_B):
        print("Los archivos son identicos.")
    else:
        print("Los archivos son distintos")

def HmacStuff():

    '''
    
        Submenú que permite la generación de HMAC para un texto entrado por el usuario, y la 
        verificación del mismo.

    '''

    print("Selecciona la operacion a realizar: ")
    print("1. Generar HMAC para texto")
    print("2. Comprobar HMAC de un texto")
    print("3. Volver")

    choice = input("Opcion(numero): ")

    if (CheckInt(choice)):

        choice = int(choice)

        match choice:
            case 1:

                workingString = input("Ingresa el texto: ")
                key = hs.GenKey()
                keyName = input("Ingrese un nombre para guardar la llave: ")

                with open (keyName, 'wb') as file:
                    file.write(key)
                print("Llave guardada en la carpeta local")

                hmac = hs.GenHmac(workingString, key)
                print(f"HMAC generado corectamente con el valor: {hmac}")

            case 2:

                workingString = input("Ingresa el texto al que quieres comprobar el HMAC: ")
                keyName = input("Ingresa el nombre del archivo que contiene la llave generada anteriormente: ")

                try:
                    with open (keyName, 'rb') as file:

                        key = file.read()

                    print("Llave cargada")

                    hmac = input("Ingresa el HMAC generado anteriormente: ")

                    if(hs.VerifyHmac(workingString, key, hmac)):
                        print("Verificacion exitosa")
                    else:
                        print("Verificacion fallida, el texto ha sido alterado")
                
                except Exception as e:

                    print("Error al abrir el archivo que contiene la llave: {e}")
                    return
                
            case 3:
                print(choice)
                return
            case _:
                print("Selecciona un numero valido")

    else:
            print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

#Auth
def AuthMenu():

    '''

        Menú que contiene la simulacion de inicio de sesión y registro de un usuario.
    
    '''

    print("Selecciona una opcion:")
    print("1. Simulacion de Login con hash y sal")
    print("2. Volver")
    choice = input("Opcion(numero): ")

    if(CheckInt(choice)):

        choice = int(choice)

        match choice:

            case 1:
                AuthSim()
            case 2:
                print("Volviendo al menu principal")
                return
            case _:
                print("Selecciona una opcion valida")
    else:
        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

def AuthSim():

    '''
    
        Subenú que permite iniciar la simulación de registro y login de un usuario utilizando
        hashing con sal para la autenticación (Utiliza easygui para la simulación de la 
        interfaz de inicio de sesión)

    '''

    sessionFlag = False

    eg.msgbox("A continuacion se comenzara la simulacion de autenticacion con hash y sal")   
    pre_msg = "Selecciona una opcion"
    pre_title = "Simulacion de autenticacion"
    pre_choices = ["Registrarse", "Iniciar Sesion", "Volver"] 

    while True:

        pre_choice = eg.buttonbox(pre_msg, pre_title, pre_choices)

        match pre_choice:
            case "Registrarse":
                
                if sessionFlag:
                    reg_choice = eg.ynbox("Ya hay una sesion iniciada. Desea salir de la sesion y registrar un usuario nuevo?")

                    if reg_choice:
                        sessionFlag = False
                        eg.msgbox("Sesion cerrada.")
                    else:

                        eg.msgbox("Sesion no cerrada")                        

                else:
                    
                    reg_msg = "Ingrese su nombre de usuario y contraseña"
                    reg_title = "Registrar usuario"
                    reg_fields = ["Nombre de usuario", "Contraseña"]
                    reg_values = []

                    reg_values = eg.multpasswordbox(reg_msg, reg_title, reg_fields)

                    while True:

                        if reg_values == None: break
                        errStr = ""

                        for counter in range(len(reg_fields)):

                            if reg_values[counter].strip() == "":
                                errStr += "FieldEmpty "
                        
                        if errStr == "": break
                        reg_values = eg.multpasswordbox("Comprueba que no haya casillas vacias", reg_title, reg_fields, reg_values)

                    user_exists = False
                    if reg_values == None: return
                    try:
                        with open ("db.md", 'r') as db:

                            content = db.read()

                            if reg_values[0] in content:
                                eg.msgbox("El usuario ya existe, por lo tanto no se registro")
                                user_exists = True
                                return
                            
                            else:
                                eg.msgbox("Usuario registrado con exito")

                    except FileNotFoundError:
                        eg.msgbox("No se pudo acceder a la base de datos")

                    if not user_exists:

                        hash, salt = hs.SaltPassword(reg_values[1], None)
                        user = hs.user(reg_values[0], hash, salt)
                        
                        try:

                            with open("db.md", 'a') as db:
                                db.write(str(user) + "\n")
                            print(str(user))
                            eg.msgbox(f"DEBUG: Guardado en base de datos como: {user}", "Guardado")
                        
                        except FileNotFoundError:
                            eg.msgbox("No se pudo acceder a la base de datos")
                            return

                        except Exception as e:
                            eg.msgbox(f"Error: {e}")
                            return    

            case "Iniciar Sesion":
                
                if sessionFlag:
                    reg_choice = eg.ynbox("Ya hay una sesion iniciada. Desea salir de la sesion e iniciar una nueva sesion?")

                    if reg_choice:
                        sessionFlag = False
                        eg.msgbox("Sesion cerrada.")
                    else:

                        eg.msgbox("Sesion no cerrada")

                else:

                    reg_msg = "Ingrese su nombre de usuario y contraseña"
                    reg_title = "Iniciar Sesion"
                    reg_fields = ["Nombre de usuario", "Contraseña"]
                    reg_values = []

                    reg_values = eg.multpasswordbox(reg_msg, reg_title, reg_fields)
                    
                    while True:

                        if reg_values == None: break
                        errStr = ""

                        for counter in range(len(reg_fields)):

                            if reg_values[counter].strip() == "":
                                errStr += "FieldEmpty "
                        
                        if errStr == "": break
                        reg_values = eg.multpasswordbox("Comprueba que no haya casillas vacias", reg_title, reg_fields, reg_values)

                    user_exists = False
                    correct_pass = False
                    db_lines = []
                    user_info = []
                    try:
                        with open ("db.md", 'r') as db:

                            db_lines = db.readlines()

                            for line in db_lines:
                                
                                line = line.strip().replace(',','')

                                if reg_values[0] in line:

                                    user_info = line.split()
                                    print(user_info)
                                    user_exists = True

                    except FileNotFoundError:
                        eg.msgbox("No se pudo acceder a la base de datos")

                    if not user_exists:
                        eg.msgbox("No existe ningun usario con ese nombre")
                        return

                    salt_bytes = ast.literal_eval(user_info[2])
                    
                    correct_pass = hs.CompareSaltedHash(reg_values[1], user_info[1], salt_bytes)
                    
                    if correct_pass:

                        eg.msgbox("Sesion iniciada con exito! (Hash autenticado correctamente)")
                        sessionFlag = True
                    
                    else:
                        eg.msgbox("Usuario o password incorrecto")
                        sessionFlag = False

            case "Volver":
                print(pre_choice)
                return

#Digital Signature
def SignMenu():
    
    '''
    
        Menú relacionado al ejercicio de firma digital.

    '''

    print("Selecciona una opcion:")
    print("1. Generar llaves")
    print("2. Firmar mensaje")
    print("3. Verificar firma")
    print("4. Volver")

    choice = input("Opcion(numero): ")

    if (CheckInt(choice)):

        choice = int(choice)

        match choice:
            case 1:
                GenKeysMenu()
            case 2:
                SignMessageMenu()
            case 3:
                VerifySignatureMenu()
            case 4:
                print("Volviendo al menu principal")
                return
            case _:
                print("Selecciona una opcion valida")

    else:
        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

def GenKeysMenu():

    '''
    
        Subenú que permite la generación de las llaves privada y pública, y su subsecuente 
        guardado en un archivo según codificación PEM

    '''

    gen_success = False

    priv = ds.GenKey()

    gen_success = ds.SaveKey(priv, "priv")

    pub = priv.public_key()

    if gen_success:

        print("Llave privada guardada con exito")
    
    else:

        print("Error al guardar llave privada")
    
    gen_success = ds.SavePublic(pub, "pub.pub")

    if gen_success:

        print("Llave publica guardada con exito")
    
    else:

        print("Error al guardar llave publica")

def SignMessageMenu():
    
    '''
    
        Subenú que permite firmar un texto que ingrese el usuario

    '''

    message = input("Ingresa el mensaje que quieres firmar: ")
    
    privKey = ds.LoadKey("priv")    
    
    signature = ds.Sign(message, privKey)
    success = ds.SaveSignature("sign", signature) 

    if success: print("Firma Guardada")
    else: print ("Error al guardar firma")
    

def VerifySignatureMenu():
    
    '''
    
        Subenú que permite verificar una firma previamente generada, según el texto que
        se entre. Si es el mismo texto exactamente, la firma será verificada con éxito

    '''

    message = input("Ingresa el mensaje que firmaste: ")
    message = message.encode()
    pubKey = ds.LoadPublic("pub.pub")
    signature = ds.LoadSignature("sign")    
    signature = bytes.fromhex(signature)
    verification = ds.Verify(message, signature, pubKey)

    if verification:
        print("La firma es valida para este mensaje")
    else:
        print("Verificacion fallida para este mensaje")

#Blockchain

def BlockMenu():

    '''
    
        Menú que permite inciar el ejercicio de ejemplo de blockchain

    '''

    print("Selecciona una opcion: ")
    print("1. Ejemplo blockchain")
    print("2. Volver")

    choice = input("Opcion(numero): ")

    if (CheckInt(choice)):

        choice = int(choice)

        match choice:
            case 1:
                BlockExample()
            case 2:
                print("Volviendo al menu principal")
                return
            case _:
                print("Selecciona una opcion valida")

    else:
        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

def BlockExample():

    '''
    
        Subenú que permite iniciar el ejemplo de creación del blockchain, nuevos bloques
        ver los bloques que pertenecen al mismo, verificar la integridad, y simular un 
        ataque por cambio de datos.

    '''

    exists = False
    chain:bc.Chain
    
    while True:

        print("Selecciona la accion que deseas realizar")
        print("1. Crear blockchain a partir de bloque genesis")
        print("2. Añadir bloque al blockchain")
        print("3. Ver Blockchain actual")
        print("4. Verificar integridad del blockchain")
        print("5. Atacar un blockchain")
        print("6. Volver")

        choice = input("Opcion(numero): ")

        if (CheckInt(choice)):

            choice = int(choice)

            match choice:
                case 1:
                    
                    if exists:
                        print("El blockchain ya existe")
                    else:

                        chain = bc.Chain()
                        exists = True
                        print("Blockchain creado")

                case 2:
                    
                    if exists:

                        data = input("Ingresa un dato para guardar en el blockchain: ")
                        chain.AddBlock(data)
                        print("Bloque añadido")

                    else:

                        print("El blockchain aun no existe")
                        

                case 3:
                    
                    if exists:

                        print("El blockchain está compuesto de los bloques: ")
                        curr = chain.GetBlocks()

                        for block in curr:
                            print(f"Bloque: {block.idx}, Datos: {block.data}, Timestamp: {block.timestamp}")
                        
                    else:

                        print("El blockchain aun no existe")
                        

                case 4:

                    if exists:

                        curr, msg = chain.ChainVerify()

                        if curr:
                            print(msg)
                        else:
                            print(f"Verificacion encontro una modificacion: {msg}")

                    else:
                        print("El blockchain aun no existe")
                
                case 5:
                    
                    if exists:
                        print("El blockchain se compone de los siguentes bloques: ")

                        blocks = chain.GetBlocks()

                        for block in blocks:
                            print(f"Bloque: {block.idx}, Datos: {block.data}, Timestamp: {block.timestamp}")

                        choice = input("Ingresa el indice del bloque a modificar: ")
                        
                        if CheckInt(choice):

                            choice = int(choice)

                            if choice < len(blocks) and choice >= 0:

                                chain.chain[choice].data = input("Ingresa el nuevo dato: ")
                                print("Dato modificado")
                            
                            else:
                                print("Selecciona un indice valido")
                        
                        else:
                            print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")

                    else:
                        print("El blockchain aun no existe")

                case 6:
                    print("Volviendo al menu principal")
                    break
                case _:
                    print("Selecciona una opcion valida")

        else:
            print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")    

#HTTP HTTPS

def WebMenu():

    '''
    
        Menú que permite la iniciación de un request web

    '''

    print("Selecciona una opcion: ")
    print("1. Request Web")
    print("2. Volver")

    choice = input("Opcion(numero): ")

    if (CheckInt(choice)):

        choice = int(choice)

        match choice:
            case 1:               
                
                while True:

                    print("Selecciona a que pagina hacer request")
                    print("1. HTTP (badssl.com)")
                    print("2. HTTPS (archlinux.org)")
                    print("3. Volver")

                    sub = input("Opcion (numero): ")

                    if CheckInt(choice):

                        sub = int(sub)

                        match sub:

                            case 1:

                                result = MakeRequest("https://expired.badssl.com/")

                                if result:
                                    print("Respuesta guardada en archivo")
                                else:
                                    print("Error SSL, guardado en archivo")

                            case 2:

                                result = MakeRequest("https://archlinux.org/")

                                if result:
                                    print("Respuesta guardada en archivo")
                                else:
                                    print("Error SSL, guardado en archivo")

                            case 3:
                                print("Volviendo")
                                break
                        
                    else:
                        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")
                                
            case 2:
                print("Volviendo al menu principal")
                return
            case _:
                print("Selecciona una opcion valida")

    else:
        print("DEBES ELEGIR UN NUMERO SEGUN LA OPCION")


def MakeRequest(url):

    '''
    
        Función que utiliza una url para hacer un simple request de GET a la página correspondiente.

        Params: 
            url: URL de cualquier sitio web
            
        Returns:
            status: Bandera que describe el estado del request.

            >False: El request falló, y se guarda en archivo el string asociado a dicho error

            >True: El request se realizó con éxito y la respuesta se guarda en un archivo

    '''

    status, response = sw.RequestTest(url)

    if status:
        WriteResponse(response.text)
        return status
    
    else:

        WriteResponse(str(response))
        return status

def WriteResponse(message):

    '''
    
        Función que realiza el guardado de la respuesta en un archivo de texto para su 
        inspección

        Params:
            message: El texto a ser escrito en el archivo
        Returns:
            bool: Bandera que describe el estado de la escritura en el archivo
            >False: La escritura en el archivo falló
            >True: La escritura del archivo fue exitosa

    '''

    try:
            with open("response.txt", 'w') as file:
                file.write(message)
                return True
            
    except:
        return False

#Execution
MainMenu()