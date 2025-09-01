import requests as rq
import certifi as cf

def RequestTest(url):

    '''
    
        Función que realiza un request simple de GET a un sitio web según su URL

        Params:
            url: URL de cualquier sitio web
        
        Returns:
            tuple:
                >bool: Bandera que describe el estado de la respuesta de la página
                    >>False: Ocurrió un error

                    >>True: Se recibió respuesta de la página
                
                >e: Un error, puede ser de conexión (RequestException) o de certificado SSL (SSLError)
    
    '''

    try:

        response = rq.get(url, timeout = (3, 10), verify=cf.where())
        response.raise_for_status()
        return True, response
    
    except rq.exceptions.SSLError as e:

        return False, e

    except rq.exceptions.RequestException as e:

        return False, e
    
