import os
import pickle
import requests
from flask import request, Response

def handler(response):
    payload = request.args.get("d")
    pickle.loads(payload)
    return response
