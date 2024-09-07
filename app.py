from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from models import mongo, init_db
from config import Config
from bson import ObjectId
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

init_db(app)

# Definit endpoint para registrar un usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"msg": "Ese usuario ya existe"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    result = mongo.db.users.insert_one({"username":username,"email":email,"password":hashed_password})

    if result.acknowledged:
        return jsonify({"msg":"Usuario creado correctamente"}),201
    else:
        return jsonify({"msg":"Hubo un error, no se pudieron agregar los datos"}),400
    
# Ruta del endpoint para el login 

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({"email":email})

    if user and bcrypt.check_password_hash(user['password'],password):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify(access_token=access_token),201
    else:
        return jsonify({"msg" : "Credenciales incorrectas"}),401

if __name__ == '__main__':
    app.run(debug=True)