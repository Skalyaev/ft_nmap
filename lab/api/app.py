from os import getenv
from fastapi import FastAPI, Depends
from sqlmodel import create_engine, Session

app = FastAPI()

driver = getenv("DRIVER_DB")
dbname = getenv("NAME_DB")
host = getenv("HOST_DB")
port = getenv("PORT_DB")
user = getenv("USER_DB")
passw = getenv("PASS_DB")

db_url = f"{driver}://{user}:{passw}@{host}:{port}/{dbname}"
engine = create_engine(db_url, echo=True)


def database():
    with Session(engine) as session:
        yield session


@app.get("/api")
async def test(db: Session = Depends(database)):
    return {"Hello": "World"}
