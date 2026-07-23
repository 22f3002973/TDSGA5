from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class RequestBody(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: str

@app.get("/")
def home():
    return {"message": "GA5 Q2 API is running"}

@app.post("/charge")
def charge(req: RequestBody):
    delta = req.new_price - req.old_price

    if req.spec == "v1":
        ans = delta * (req.days_remaining / 30)
    elif req.spec == "v2":
        ans = delta * (req.days_remaining / req.days_in_actual_month)
    else:
        return {"error": "Invalid spec"}

    return {"charge": round(ans, 2)}