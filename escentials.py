import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
def rutaHome(ubicacion : str = ""):
    ruta = ""
    if ubicacion == "":
        ruta = os.path.expanduser("~/Server")
    else:
        ruta = os.path.join(os.path.expanduser("~/Server"), ubicacion)
    return ruta

def verificarProd():
    ruta = rutaHome("Credentials/logo.svg")
    try:
        with open(ruta, "rb") as prod:
            archivo = prod.read()
        archivoc = archivo.decode("utf-8")
        if archivoc == "PROD=false":
            return {"message" : "Server in mainteinment", "status" : False, "code" : 404}
        elif archivoc == "PROD=true":
            return {"message" : "Server in mainteinment", "status" : True, "code" : 500}
        else:
            return {"message" : "Server hacked or corrupted\nLet's reset evruthing!!! NOW!!!", "status" : False, "code" : 404}
    except Exception as e:
        return {"message" : "Error al procesar la informacion", "status" : False, "code" : 404}

def obtener_llaves_privadasApis(directorio: str):
    return [os.path.join(directorio, f) for f in os.listdir(directorio) if f.endswith(".key")]


def buscarLlavePriv(llPub):
    #Aqui pondremos lo que pasará si esta en funcionamiento, osea, regresar la llave AES y el IV del server
    frase = "Γνῶθι σεαυτόν, καὶ σὺν Ἀπόλλωνι ἔσεσθαι"
    direccion = obtener_llaves_privadasApis(rutaHome("myDaughter"))
    mensaje_bytes = frase.encode("utf-8")
    encrypted = llPub.encrypt(
        mensaje_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    for i in direccion:
        #Aqui tenemos todas las llaves privadas
        with open(i, "rb") as llave1:
            llave = llave1.read().decode("utf-8")
        private_key = serialization.load_pem_private_key(
            llave.encode("utf-8"),
            password=None,
            backend=default_backend()
        )
        mensaje_descifrado = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        if mensaje_descifrado.decode("utf-8") == frase:
            #Aqui estamos retornando la llave privada
            return llave
        else:
            return None
    

def verificarLlaveApi(body):
    
    #parseando llave publica:
    public_key = serialization.load_pem_public_key(
        body.encode(),
        backend=default_backend()
    )
    #Aqui pondremos lo que pasará si esta en funcionamiento, osea, regresar la llave AES y el IV del server
    if buscarLlavePriv(public_key) is not None:
        return True
    else:
        return False
def descifradoRSAServer(texto):
    with open(rutaHome("Credentials/private_key.pem"), "rb") as archivo:
        llave = archivo.read().decode("utf-8")
    text  = bytes.fromhex(texto)
    private_key = serialization.load_pem_private_key(
        llave.encode("utf-8"),
        password=None,
        backend=default_backend()
    )
    try:
        mensaje_descifrado = private_key.decrypt(
            text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"message": mensaje_descifrado.decode("utf-8"), "code" : 200, "status" : True}
    except Exception as e:
        return {"message" : "Llave incorrecta o inaceptable\n" + str(e), "code" : 404, "status" : False}
