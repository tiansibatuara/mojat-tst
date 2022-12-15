from flask import Flask, render_template, request, jsonify, redirect, session
from route.user import blueprint as user_blueprint
from services.database_Service import conn as cur
from dotenv import load_dotenv
from decimal import Decimal
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from sqlalchemy import text
import bcrypt
import requests
import jwt
import secrets
import re
import json

load_dotenv()
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

app.config["SECRET_KEY"] = "secret"
app.config["MAIL_PORT"] = 587
app.config["MAIL_SERVER"] = "imap.gmail.com"
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_DEFAULT_SENDER"] = "sibatuarachristian@gmail.com"
app.config["MAIL_USERNAME"] = "sibatuarachristian@gmail.com"
app.config["MAIL_PASSWORD"] = "sbbwxwbusamrkoku"

mail = Mail(app)

app.register_blueprint(user_blueprint)

@app.route('/')
def hello_world():  # put application's code here
    return 'Hello! This is Mozart!'

# Authentication

def otpHandler(data):
  otp = secrets.token_hex(3)
  session["otp"] = otp  # Store the OTP in the session
  msg = Message("Your OTP, Happy Coding!", recipients=[data['email']])
  msg.body = f"Your OTP is {otp}"
  mail.send(msg)

  return "Successfully sending OTP request! Please check your email!"

def checkUserAvailable(cur, data):
    result = cur.execute('SELECT * FROM user WHERE email=%s', (data['email'],))
    return result.rowcount > 0

def checkToken(bearer):
  try:
    token = bearer.split()[1]
    decodedToken = jwt.decode(token, "secret", algorithms=['HS256'])
    date_str = decodedToken['exp_date']
    tokenDate = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    if (tokenDate < datetime.now()):
      raise

    return True
  except:
    return False

def checkOTP(otp):
  sessionOtp = session.get('otp')
  if (otp == sessionOtp):
    try:
      createUser()
    except:
      return "Failed to create user", 400

    session.clear()
    return "Success creating new account!", 201

  else: 
    return "Wrong OTP!", 200

def validEmail(email):
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if re.match(regex, email):
        return True
    return False

def createUser():
  data = session.get('user_cred')

  encodedPass = encodeStr(data['password'])

  cur.execute('INSERT INTO user(email, password) VALUES (%s, %s) ', (data['email'], encodedPass))

@app.route('/sign-up', methods=['GET', 'POST'])
def signUp():
  json_data = request.json

  otp = request.args.get('otp')
  if (otp):
    return checkOTP(otp)

  data = {
    'email': json_data['email'],
    'password': json_data['password']
    }
  session['user_cred'] = data

  if not validEmail(data['email']):
    return "Please enter a valid Email", 401

  if checkUserAvailable(cur, data):
    return "Your email or Password is already used!", 401

  else:
    try:
      res = otpHandler(data)
    except:
      return "Failed to send OTP! Please retry!", 400
    return res, 200

@app.route('/log-in', methods=['GET', 'POST'])
def logIn():
    json_data = request.json

    data = {
        "email": json_data['email'],
        "password": json_data['password'],
    }

    for user in cur.execute(' SELECT * FROM user WHERE email=%s LIMIT 1', (data['email'],)):
        if (verifyUser(data['password'], user['password'])):
            date = datetime.now() + timedelta(days=7)
            date_str = date.strftime("%Y-%m-%dT%H:%M:%S")
            token = jwt.encode({'exp_date' : date_str}, "secret")
            return jsonify(
                {
                'message': 'Please save this token and use it to access our provided API! This token will last for 7 Days',
                'token' : token
                }), 201
    return "No available email! Please sign in", 404

# Main App

@app.route('/playerByName', methods=['GET', 'POST'])
def playerByName(): 
  player_name = request.args.get('name')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
    
  rows = []
  for pinfo in cur.execute(text("SELECT * FROM datasetplayer WHERE Player LIKE :pname ;"), {"pname": f"%{player_name}%"}):
    rows.append(pinfo)
  print(rows)
  player_info = []
  
  for p in rows:
    deci =  Decimal(6.0) + p[15] * Decimal(0.01) + p[24] * Decimal(0.01) + p[88] * Decimal(0.01) + p[92] * Decimal(0.01) + p[113] * Decimal(0.01) + p[126] * Decimal(0.01) + p[142] * Decimal(0.01)
    player_info.append({
      "Rk" : p[0],
      "Name" : p[1],
      "Nation" : p[2],
      "Position" : p[3],
      "Rating": str('%.3f' % deci),
    })
  print(player_info)
  return jsonify(player_info)

@app.route('/playerByRk', methods=['GET', 'POST'])
def playerByRk(): 
  Rk = request.args.get('Rk')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
    
  rows = []
  for pinfo in cur.execute(text("SELECT * FROM datasetplayer WHERE Rk =:pid"), {"pid": Rk}):
    rows.append(pinfo)
  player_info = []
  
  for p in rows:
    deci =  Decimal(6.0) + p[15] * Decimal(0.01) + p[24] * Decimal(0.01) + p[88] * Decimal(0.01) + p[92] * Decimal(0.01) + p[113] * Decimal(0.01) + p[126] * Decimal(0.01) + p[142] * Decimal(0.01)
    player_info.append({
      "Rk" : p[0],
      "Name" : p[1],
      "Nation" : p[2],
      "Position" : p[3],
      "Rating": str('%.3f' % deci),
    })
  print(player_info)
  return jsonify(player_info)

@app.route('/addPlayer', methods=['POST'])
def addPlayer():
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
  
  body = request.json

  payload = {
    "Name": body['Name'],
    "Nation": body['Nation'],
    "Position": body['Position'],
    "Squad" : body['Squad'],
    "SoTP" : body['SoTP'],
    "PasTotCmpP" : body['PasTotCmpP'],
    "TklDriP" : body['TklDriP'],
    "PressP" : body['PressP'],
    "DriSuccP" : body['DriSuccP'],
    "RecP" : body['RecP'],
    "AerWonP" :  body['AerWonP']
  }
  cur.execute("INSERT INTO datasetplayer (Player, Nation, Pos, Squad, SoTPercent, PasTotCmpPercent, TklDriPercent, PressPercent, DriSuccPercent, RecPercent, AerWonPercent) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (payload['Name'], payload['Nation'], payload['Position'], payload['Squad'], payload['SoTP'], payload['PasTotCmpP'], payload['TklDriP'], payload['PressP'], payload['DriSuccP'], payload['RecP'], payload['AerWonP']))
  return jsonify(payload)

@app.route('/updatePlayer', methods=['PUT'])
def updatePlayer():
  Rk = request.args.get('Rk')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404


  body = request.json

  payload = {
    "Rk": Rk,
    "Name": body['Name'],
    "Nation": body['Nation'],
    "Position": body['Position'],
    "Squad" : body['Squad'],
    "SoTP" : body['SoTP'],
    "PasTotCmpP" : body['PasTotCmpP'],
    "TklDriP" : body['TklDriP'],
    "PressP" : body['PressP'],
    "DriSuccP" : body['DriSuccP'],
    "RecP" : body['RecP'],
    "AerWonP" :  body['AerWonP']
  }
  
  cur.execute("UPDATE datasetplayer SET Player = %s, Nation = %s, Pos = %s, Squad = %s, SoTPercent = %s, PasTotCmpPercent = %s, TklDriPercent = %s, PressPercent = %s, DriSuccPercent = %s, RecPercent = %s, AerWonPercent = %s WHERE Rk = %s", (payload['Name'], payload['Nation'], payload['Position'], payload['Squad'], payload['SoTP'], payload['PasTotCmpP'], payload['TklDriP'], payload['PressP'], payload['DriSuccP'], payload['RecP'], payload['AerWonP'], payload['Rk']))
  return jsonify(payload)


@app.route('/deletePlayer')
def deletePlayer():
  Rk = request.args.get('Rk')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  cur.execute("DELETE FROM datasetplayer WHERE Rk = %s", (Rk,))
  return f"Delete player success! [Rk = {Rk}]"

@app.route('/dreamTeam', methods=['GET', 'POST'])
def dreamTeam():
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
 
  
  body = request.json

  payload = {
    "id1" : body['id1'],
    "id2" : body['id2'],
    "id3" : body['id3'],
    "id4" : body['id4'],
    "id5" : body['id5'],
    "id6" : body['id6'],
    "id7" : body['id7'],
    "id8" : body['id8'],
    "id9" : body['id9'],
    "id10" : body['id10'],
    "id11" : body['id11']
  }

  rows = []
  for pinfo in cur.execute("SELECT *  FROM `datasetplayer` WHERE Rk IN (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);", (payload["id1"], payload["id2"], payload["id3"], payload["id4"], payload["id5"], payload["id6"], payload["id7"], payload["id8"], payload["id9"], payload["id10"], payload["id11"])):
    rows.append(pinfo)

  player_info = []
  players_rate = 0
  expectedGoals = 0
  for p in rows:
    deci =  Decimal(6.0) + p[15] * Decimal(0.01) + p[24] * Decimal(0.01) + p[88] * Decimal(0.01) + p[92] * Decimal(0.01) + p[113] * Decimal(0.01) + p[126] * Decimal(0.01) + p[142] * Decimal(0.01)
    hitung = p[12]/p[13]
    hitung2 = hitung * Decimal(100)
    player_info.append({
      "Rk" : p[0],
      "Name" : p[1],
      "Rating": str('%.3f' % deci)
    })
    expectedGoals += hitung 
    players_rate += deci
  team_rate = float(players_rate/11)
  team_expectedGoal = float(expectedGoals/11)
  response = {"Team Rating": team_rate, "Expected Goal": team_expectedGoal, "Team Players": player_info}

  return jsonify(response)

@app.route('/useFTCore', methods=['GET'])
def useFTCore():
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  body = request.json

  dataLogin = {
    'email' : body['email'],
    'password': body['password'],
    }

  dataTeam = {
    'Team 1 Id': body["Team 1 Id"],
    'Team 2 Id': body["Team 2 Id"]
  }

  response = requests.post('http://206.189.80.94:5000/log-in', json = dataLogin)
  result = response.json()
  
  tokenKai = result['token']

  response2 = requests.get('http://206.189.80.94:5000/winPredict?Authorization=Bearer %s' % (tokenKai), json = dataTeam)
  result2 = response2.json()

  winnerTeam = result2["Winner Team Prediction"]

  rows = []
  for winfo in cur.execute(text("SELECT * FROM `datasetplayer` WHERE Squad LIKE :sq ;"), {"sq" : f"%{winnerTeam}%"}):
    rows.append(winfo)

  mvpPredict =[]
  for p in rows:
    deci =  Decimal(6.0) + p[15] * Decimal(0.01) + p[24] * Decimal(0.01) + p[88] * Decimal(0.01) + p[92] * Decimal(0.01) + p[113] * Decimal(0.01) + p[126] * Decimal(0.01) + p[142] * Decimal(0.01)
    mvpPredict.append({
      "Rk" : p[0],
      "Name" : p[1],
      "Nation" : p[2],
      "Position" : p[3],
      "Rating": str('%.3f' % deci),
    })

  sorted_players = sorted(mvpPredict, key=lambda x: x['Rating'], reverse=True)
  
  res = []
  if len(sorted_players) > 5:
    for i in range(5):
      res.append(sorted_players[i])


  response = {"Winner Team": winnerTeam, "MVP Prediction": res}
  return jsonify(response)

# Auth

key = "tiantampan"

def encodeStr(ePass):
  hashed_password = bcrypt.hashpw((key+ePass).encode("utf-8"), bcrypt.gensalt())
  return hashed_password

def verifyUser(ePass, cPass):
  return bcrypt.checkpw((key+ePass).encode("utf-8"), cPass.encode("utf-8"))

if __name__ == '__main__':
    app.run()
