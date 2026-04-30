import os
import pickle
import requests
from flask import request, Response

def handler(response):
    name = request.args.get("name")
    response.write("<h1>" + name + "</h1>")
    return response
