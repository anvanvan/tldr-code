import os
import pickle
import requests
from flask import request, Response

def handler(response):
    u = request.args.get("u")
    requests.get(u)
    return response
