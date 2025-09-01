import hashlib as hl
import time as t

class Block:

    '''
    
        Clase que describe el objeto Bloque.

        Attributes:
            idx: El índice del bloque dentro del blockchain
            timestamp: La etiqueta de tiempo de creación con respecto al 1º de enero de 1970, en segundos
            data: Los datos contenidos por el bloque. Pueden ser de cualquier tipo, pero por simplicidad solo se insertan strings
            prev_hash: El hash SHA-256 del bloque anterior.
            hash: El hash SHA-256 propio
    
    '''

    def __init__(self, idx, data, prev_hash):

        '''
        
            Constructor con parámetros, permite la instanciación de un objeto nuevo de clase Block con parámetros definidos

            Params:
                idx: El indice asignado en la creación de la instancia
                timestamp: Tiempo en el que se instanció el objeto
                data: Datos a almacenar en el objeto
                prev_hash: Hash del bloque inmediatamente anterior
                hash: Hash propio calculado en la creación del mismo según los otros parámatros
        
        '''

        self.idx = idx
        self.timestamp = t.time()
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.CalcHash()

    def CalcHash(self):

        '''
        
            Función de cálculo del hash SHA-256 de un objeto Block

            Params:
                self: El objeto instanciado

            Returns:
                hash: El hash SHA-256 calculado en modo hexadecimal

        '''

        block_str = str(self.idx) + str(self.timestamp) + str(self.data) + str(self.prev_hash)
        return hl.sha256(block_str.encode()).hexdigest()

class Chain:

    '''
    
        Clase que describe el objeto Chain

        Attributes:
            chain: Una autoreferencia que permite obtener una lista de todos los bloques encadenados
    
    '''

    def __init__(self):

        '''
            
            Constructor que permite la generación del bloque Génesis

            Params:
                self: El objeto instanciado
        
        '''

        self.chain = [self.GenBlock()]

    def GetBlocks(self):

        '''

            Función que devuelve una lista de los bloques encadenados

            Params:
                self: El objeto instanciado
            Returns:
                chain: Lista de todos los bloques pertenecientes a la cadena

        '''

        return self.chain

    def GenBlock(self):

        '''

            Función que devuelve el bloque génesis para empezar el blockchain

            Params:
                self: El objeto instanciado
            
            Returns:
                block: El bloque génesis con datos predeterminados e indice 0
        
        '''

        return Block(0, "Genesis", 0)
    
    def LastBlock(self):

        '''
        
            Función que devuelve el último bloque de la cadena

            Params:
                self: El objeto instanciado
            
            Returns:
                chain: Objeto Block al final de la lista de la cadena
        '''

        return self.chain[-1]
    
    def AddBlock(self, data):

        '''
        
            Función que permite añadir más bloques con datos ingresados por el usuario. Los bloques son añadidos
            al final de la cadena

            Params:
                self: El objeto instanciado
                data: Datos ingresados por el usuario en tiempo de ejecución
        
        '''

        last = self.LastBlock()
        new = Block(len(self.chain), data, last.hash)
        self.chain.append(new)

    def ChainVerify(self):
        
        '''
        
            Función que verifica la integridad del blockchain, comparando los hashes propios y del bloque anterior en
            el caso de cualquier bloque con excepción del bloque génesis, el cual solamente realiza la comparación
            de su propio hash

            Params:
                self: El objeto instanciado

            Returns:
                tuple: 
                    >Primer valor: Bandera que describe el estado de la integridad del blockchain
                    
                    >Segundo valor: String que contiene el mensaje asociado al estado encontrado
        
        '''

        for counter, block in enumerate(self.chain):

            if block.hash != block.CalcHash():
                return False, "Bloque alterado"
            
            if counter > 0 and block.prev_hash != self.chain[counter - 1].hash:
                return False, "Cadena rota"

        return True, "Integridad verificada"

            
