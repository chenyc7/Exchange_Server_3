from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, MetaData, Table
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

#These decorators allow you to use g.session to access the database inside the request code
@app.before_request
def create_session():
    g.session = scoped_session(DBSession) #g is an "application global" https://flask.palletsprojects.com/en/1.1.x/api/#application-globals

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    g.session.commit()
    g.session.remove()

"""
-------- Helper methods (feel free to add your own!) -------
"""

def log_message(d)

    log_obj = Log(message = json.dumps(d))
    g.session.add(log_obj)
    g.session.commit()
    return 


"""
---------------- Endpoints ----------------
"""
    
@app.route('/trade', methods=['POST'])
def trade():
    if request.method == "POST":
        
        content = request.get_json(silent=True)
        #print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]
        error = False
        
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            log_message(content)
            return jsonify( False )


        validSig = verify(content)

        if validSig == False:
            
            print(json.dumps(content))
            log_message(content)
            return jsonify(False)
        
        else:   

            print(content)
            payload = content['payload'] 
            order_obj = Order(sender_pk = payload['sender_pk'],
                receiver_pk = payload['receiver_pk'],
                buy_currency = payload['buy_currency'],
                sell_currency = payload['sell_currency'],
                buy_amount = payload['buy_amount'],
                sell_amount = payload['sell_amount'], 
                signature = content['sig'])

            g.session.add(order_obj)
            g.session.commit()

        return jsonify( True )



        #Your code here
        #Note that you can access the database session using g.session

@app.route('/order_book')
def order_book():
    #Your code here

    result = {}
    result["data"] = []

    orders = g.session.query(Order).all()

    for order in orders:
        columns = ['sender_pk', "receiver_pk", "buy_currency", "sell_currency","buy_amount","sell_amount","signature"]

        for order in orders:
            dic = {}
            dic['sender_pk'] = order.sender_pk
            dic['receiver_pk'] = order.receiver_pk
            dic['buy_currency'] = order.buy_currency
            dic['sell_currency'] = order.sell_currency
            dic['buy_amount'] = order.buy_amount
            dic['sell_amount'] = order.sell_amount
            dic['signature'] = order.signature
            result["data"].append(dic)

    #Note that you can access the database session using g.session
    return jsonify(result)


def verify(content):
    payload = content['payload']
    sig = str(content['sig'])
    platform = str(payload['platform'])
    pk = str(payload['sender_pk'])
    result = False

    payload =  json.dumps(payload)

    if platform == 'Ethereum':
        result = False
        eth_encoded_msg = eth_account.message.encode_defunt (text = payload)
        if eth_account.Account.recover_message (eth_encoded_msg， signature = sig) == pk:
            result = True

    if platform == 'Algorand':
        if algosdk.util.verify_bytes(payload.encode ('utf-8'),sig,pk):
            result = True
    return result


if __name__ == '__main__':
    app.run(port='5002')
