import os
import pickle
import requests
from flask import request, Response

def handler(response):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM u WHERE id = " + user_id)
    return response
