"""
vt=PathTraversal lang=python — names below are inside strings/comments only

Documentation example (these patterns are NOT executed):
  x = request.args.get("id")
  cursor.execute("SELECT ... " + x)
  os.system(x)
  open(x, "r")
  requests.get(x)
  pickle.loads(x)
  response.write(x)
"""

DOC = """
request.args, cursor.execute, os.system, open(, requests.get, pickle.loads, response.write
"""

def docs_only():
    # also: request.args.get("id") + cursor.execute(...) — comment only
    msg = "request.args.get + cursor.execute + os.system + open( + requests.get + pickle.loads"
    return msg
