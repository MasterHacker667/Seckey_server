from pydantic import BaseModel

class descifrador(BaseModel):
    key: str
    text : str