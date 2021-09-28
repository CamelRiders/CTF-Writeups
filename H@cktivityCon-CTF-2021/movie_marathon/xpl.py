# Author: Canlex

from pwn import *
import requests
import urllib.parse
import json

APIV3 ="your_api_key_to_themovidedb.org" # change it to the your api key from themoviedb.org
HOST = "challenge.ctf.games"
PORT = 31260 # change to your instance port

context.log_level = "critical"


def get_movie_id(name, year):
    name = urllib.parse.quote(name)
    req = requests.get(f"https://api.themoviedb.org/3/search/movie?api_key={APIV3}&query={name}&year={year}")
    x = json.loads(req.content)
    for i in x["results"]:
        if "release_date" in i.keys():
            if i["release_date"] == date.decode():
               return i["id"]

def get_cast(id):
    lst = []
    req = requests.get(f"https://api.themoviedb.org/3/movie/{movie_id}/credits?api_key={APIV3}&language=en-US")
    x = json.loads(req.content)
    for i in x["cast"]:
        lst.append(i["name"].encode())
        if(len(lst) == 5):
            return b"; ".join(lst)



r = remote(HOST, PORT)

r.recv(0x1ce)

for i in range(31):
    print(i)
    if(i!=30):
        x = r.recvuntil(b"> ")
        name, date = r.recvline().split(b" (")
        date = date[:-2]
        year = date[:4]
        movie_id = get_movie_id(name, year)
        cast =get_cast(movie_id)
        
        r.sendlineafter(b"* ", cast)
    else:
        print(r.recvall().decode())