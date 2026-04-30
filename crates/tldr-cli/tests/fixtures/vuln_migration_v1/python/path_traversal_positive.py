import os
import pickle
import requests
from flask import request, Response

def handler(response):
    p = request.args.get("p")
    open(p, "r").read()
    return response
