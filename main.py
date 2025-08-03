

from fastapi import FastAPI, Body, Request, HTTPException
from modelos import descifrador
from escentials import rutaHome, verificarProd, verificarLlaveApi, descifradoRSAServer
import json
import logging
logging.getLogger("uvicorn.access").disabled = True
app = FastAPI()

#@app.middleware("http")
#async def limit_body_size(request: Request, call_next):
#    max_body_size = 351791  # bytes (ajusta según necesidad)
#    if request.method == "POST":
#        body = await request.body()
#        if len(body) > max_body_size:
#            raise HTTPException(status_code=413, detail="Request body too large")
#    return await call_next(request)



@app.post("/getserverkey")
async def getServerKey(body: str = Body(...)): #Devuelve la llave publica del servidor
    #Codigo para obtener la llave AES del servidor SIEMPRE Y CUANDO la PROD este en true
    #Checando prod
    request1 = verificarProd()
    if not request1["status"]:
        return request1
    #Verificando que la llave dada sea correcta
    if verificarLlaveApi(body):
        with open(rutaHome("Credentials/public_key.pem"), "rb") as archivo:
            llavePub = archivo.read()
        return llavePub.decode("utf-8")
    else:
        return {"status" : False, "message" : "Your key is invalid", "code" : 404}
@app.post("/descifrarserver")
async def getDescifertext(text: descifrador): #Descifra con la llave privada del servidor -> Recibe un JSON {key, text} el text debe estar cifrado en RSA si, pero el formato debe ser hex
    #Primero verificamos que el servidor no esté en modo producción
    text = {
        "key" : text.key,
        "text" : text.text
    }
    request1 = verificarProd()
    if not request1["status"]:
        return request1
    #Verificando que la llave dada sea correcta
    if verificarLlaveApi(text["key"]):
        #Aqui ponemos el codigo para descifrar algo con la llave privada del servidor
        
        textoDescifrado = descifradoRSAServer(text["text"])
        if textoDescifrado["status"]:
            return textoDescifrado["message"]
        else:
            return textoDescifrado
    else:
        return {"status" : False, "message" : "Your key is invalid", "code" : 404}
@app.post("/getaesserverrver")
async def getaeskey(body: str = Body(...)):
    request1 = verificarProd()
    if not request1["status"]:
        return request1
    #Verificando que la llave dada sea correcta
    if verificarLlaveApi(body):
        with open(rutaHome("AESKeyServer/presentacion2.pptx"), "rb") as archivo:
            llavePub = archivo.read()
        return llavePub.decode("utf-8")
    else:
        return {"status" : False, "message" : "Your key is invalid", "code" : 404}
    
@app.post("/getivserverrver")
async def getivkey(body: str = Body(...)):
    request1 = verificarProd()
    if not request1["status"]:
        return request1
    #Verificando que la llave dada sea correcta
    if verificarLlaveApi(body):
        with open(rutaHome("IVGenServer/presentacion1.pptx"), "rb") as archivo:
            llavePub = archivo.read()
        return llavePub.decode("utf-8")
    else:
        return {"status" : False, "message" : "Your key is invalid", "code" : 404}