#-*- coding: utf-8 -*-
from flask import Flask, request, Response, jsonify
# from flask_restful import Resource
from flask_restplus import reqparse, Resource

from utils.crypt import session_cipher
import utils.crypt as crypt
import json
json_encode = json.JSONEncoder().encode
import traceback
#pip install werkzeug==0.16.0 설치 필요 reqparse 사용시
import utils.db as db
import utils.common as common
from utils.common import log_access
import time

import os
import sys
sys.path.insert(0, os.path.abspath('..'))
import settings
import requests

def response(**kwargs):
    params = ['status', 'message', 'result']
    for param in params:
        if param not in kwargs.keys():  
            kwargs[param] = None

    return kwargs

def response_item_add(f_Response, add_item={}):
    f_response = json.loads(f_Response.response[0])
    f_headers = f_Response.headers
    f_mimetype = f_Response.mimetype
    
    for k,v in add_item.items():
        f_response[k] = v
        
    return Response(json_encode(f_response), headers=f_headers, mimetype=f_mimetype)

def is_jonathan_token_valid(request):
    token = request.headers.get("Authorization") or ""
    headers = {"Authorization": token}
    res = requests.get(settings.LOGIN_VALIDATION_CHECK_API, headers=headers)
    if res.status_code == 200:
        print("Jonathan Platform Token is valid")
        return True
    else:
        print("Jonathan Platform Token is not valid")
        return False


import functools
def token_checker(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if settings.NO_TOKEN_VALIDATION_CHECK == True:  
            return f(*args, **kwargs)
        TOKEN_EXPIRED_TIME = 3600
        TOKEN_UPDATE_TIME = 1 #TOKEN_EXPIRED_TIME + 3600
        TOKEN_VALIDATE_TIME = 2
        result = {"status": None, "message": None}
        fail_response = { "status": 0, "expired": True }
        header_token = ""
        try:
            header_user = request.headers.get('Jf-User')
            header_token = request.headers.get('Jf-Token')
            header_session = request.headers.get('Jf-Session')

            if settings.LOGIN_METHOD == "jonathan":
                if header_user in ["root", "lyla", "daehan-acriil", "yeobie", "edgar", "daehan", "will", "robert", "irene", "jake", "jason","lico"]: # root 는 통합 토큰 체크 안함
                    return f(*args, **kwargs)
                else:
                    if not is_jonathan_token_valid(request):
                        return send(fail_response)

            if header_token == "robert":
                # Master Token Free pass
                return f(*args, **kwargs)
            elif header_user is None or header_token is None:
                fail_response["message"] = "Header not exist"
                return send(fail_response)
            elif header_user == "login" and header_token == "login":
                print("Login Step")
                result =  {"status": True, "login": True}

            token_user, start_timestamp, gen_count = session_cipher.decrypt(header_token).split("/")
            if header_user != token_user:
                print("Header data is invalid")
                fail_response["message"] = "Header data invalid"
                return send(fail_response)
            
            db_user_info = db.get_user(user_name=header_user)
            if header_user != db_user_info["name"]:
                print("Token data is invalid")
                fail_response["message"] = "Token data invalid"
                return send(fail_response)

            session_info, message = db.get_login_session(session_id=header_session)
            if session_info is None:
                fail_response["message"] = "Not logined"
                return send(fail_response)

            # print("HEADER ", header_token, int(time.time()) - int(float(start_timestamp)))
            session_token_user, session_start_timestamp, session_gen_count = session_cipher.decrypt(session_info["token"]).split("/") 
            last_call_timestamp = common.date_str_to_timestamp(session_info["last_call_datetime"])

            if header_token != session_info["token"]:
                valid_time = int(time.time()) - int(float(start_timestamp)) < TOKEN_VALIDATE_TIME
                valid_gen_count_op1 = int(session_gen_count) - int(gen_count) < 2
                valid_gen_count_op2 = int(session_gen_count) >= int(gen_count)
                if valid_time:
                    print("Already Updated Token But still valid")
                    return f(*args, **kwargs)
                elif not valid_time and (valid_gen_count_op1 and valid_gen_count_op2):
                    print("Already Updated Token But still valid2")
                    return f(*args, **kwargs)
                else :
                    fail_response["message"] =  "Changed Token or Logouted by other login"
                    return send(fail_response)

            
            if int(time.time()) - int(last_call_timestamp) > TOKEN_EXPIRED_TIME:
                db.delete_login_session(header_token, db_user_info["id"])
                fail_response["message"] =  "Expired Token "
                return send(fail_response)

            # print("ST " , int(start_timestamp), (time.time()))
            if int(time.time()) - int(float(start_timestamp)) > TOKEN_UPDATE_TIME:
                #Token Update
                print("UPDATE TOKEN !!!")
                #TODO 갱신 안정화 필요 (token 날렸는데 업데이트 안하는 경우 발생 (프론트의 비동기? 때문?), 
                #TODO 토큰에 추가 정보가 필요할 수 있음(몇번 째 콜 횟수 라던가)
                new_token = crypt.gen_user_token(header_user, int(gen_count)+1)
                db.update_login_session_token(old_token=header_token, new_token=new_token)
                header_token = new_token
                result["token"] = new_token
                f_Response = f(*args, **kwargs)
                return response_item_add(f_Response, {"token": new_token})
            else :
                db.update_login_session_last_call_datetime(token=header_token)
            
            # return send(result)
        except Exception as e:
            print("Cath ", header_token)
            traceback.print_exc()
            result =  {"status": False, "message": "Invalid Token "}
            return send(result)
        
        return f(*args, **kwargs)

    return decorated_function



class CustomResource(Resource):
    def __init__(self,api=None, *args, **kwargs):
        super().__init__(api, args, kwargs)

    def is_root(self):
        #print ('login_name should get from session') #TODO
        try:
            if request.headers.get('Jf-User'):
                login_name = request.headers['Jf-User']
                if login_name == 'root':
                    return True, ""
        except:
            traceback.print_exc();
        # return False, response(status=0,message="Permission Error. Not root")
        return False, ""

    def is_admin_user(self):
        is_admin = False
        try:
            user_name = self.check_user()
            rows = db.execute_and_fetch('SELECT id, user_type FROM user WHERE name=%s', (user_name,))
            if rows[0]['user_type'] == 0:
                is_admin = True
        except:
            traceback.print_exc()
            raise ValueError('User {} does not exist.'.format(user_name))
        return is_admin

    def check_user(self):
        ## 유저 권한은 무엇으로 체크 ?
        #print ('user_name should get from session') #TODO
        ret_user = None
        try:            
            if request.headers.get('Jf-User'):                
                user_name = request.headers['Jf-User']                
                if type(user_name) == str:
                    return user_name
                else:
                    return None
        except:
            traceback.print_exc();
        return ret_user

    def check_token(self):
        token = None
        try:            
            if request.headers.get('Jf-Token'):
                token = request.headers['Jf-Token']                
                if type(token) == str:
                    return token
                else:
                    return None
        except:
            traceback.print_exc();
        return token

    def check_user_id(self):
        print ('user_id should get from session') #TODO
        rows = db.execute_and_fetch('SELECT id FROM user WHERE name=%s', (self.check_user(),))
        try:
            user_id = rows[0]['id']
        except:
            user_id = None
            #TODO redirect to logout. remove sesssion.
        return user_id

    def login_session_check_and_update(self):
        # return False, "ROBERT TEST"
        TOKEN_EXPIRED_TIME = 3600 * 8
        TOKEN_UPDATE_TIME = TOKEN_EXPIRED_TIME + 3600
        TOKEN_VALIDATE_TIME = 10
        result = {"status": None, "message": None}
        header_token = ""
        try:
            header_user = request.headers.get('Jf-User')
            header_token = request.headers.get('Jf-Token')
            if header_token == "robert":
                # Master Token Free pass
                return {"status": True}
            if header_user is None or header_token is None:
                return {"status": False, "message": "Header not exist"}
            if header_user == "login" and header_token == "login":
                return {"status": True, "login": True}

            token_user, start_timestamp = session_cipher.decrypt(header_token).split("/")
            if header_user != token_user:
                print("Header data is invalid")
                return {"status": False, "message": "Header data invalid"}
            
            db_user_info = db.get_user(user_name=header_user)
            if header_user != db_user_info["name"]:
                print("Token data is invalid")
                return {"status": False, "message": "Token data invalid"}


            session_info, message = db.create_ingress(token=header_token)
            if session_info is None:
                print("HEADER ", header_token, int(time.time()) - int(float(start_timestamp)))
                if int(time.time()) - int(float(start_timestamp)) < TOKEN_VALIDATE_TIME :
                    print("Already Updated Token But still valid")
                    return {"status": True, "message": ""}
                return {"status": False, "message": "Changed Token or Logouted by other login"}

            last_call_timestamp = common.date_str_to_timestamp(session_info["last_call_datetime"])
            if int(time.time()) - int(last_call_timestamp) > TOKEN_EXPIRED_TIME:
                db.delete_login_session(header_token, db_user_info["id"])
                return {"status": False, "message": "Expired Token ", "token": header_token, "user": header_user}

            # print("ST " , int(start_timestamp), (time.time()))
            if int(time.time()) - int(float(start_timestamp)) > TOKEN_UPDATE_TIME:
                #Token Update
                print("UPDATE TOKEN !!!")
                #TODO 갱신 안정화 필요 (token 날렸는데 업데이트 안하는 경우 발생 (프론트의 비동기? 때문?), 
                #TODO 토큰에 추가 정보가 필요할 수 있음(몇번 째 콜 횟수 라던가)
                new_token = crypt.gen_user_token(header_user, int(gen_count)+1)
                db.update_login_session_token(old_token=header_token, new_token=new_token)
                header_token = new_token
                result["token"] = new_token
                result["status"] = True
            else :
                db.update_login_session_last_call_datetime(token=header_token)
                result["status"] = True
            
            return result
        except Exception as e:
            print("Cath ", header_token)
            traceback.print_exc()
            return {"status": False, "message": "Invalid Token "}

    def send(self,*args, **kwargs):
        ## {result , message } 
        headers = {}
        headers['Access-Control-Allow-Origin'] = '*'
        headers['Access-Control-Allow-Headers'] = '*'
        headers['Access-Control-Allow-Credentials'] = True
        
        response_body = {'result' : None , 'message' : None}

        # print(request.headers)
        for arg in args:
            if arg is not None:
                for key in arg.keys():
                    response_body[key] = arg[key]

        for param_key in kwargs.keys():
            response_body[param_key] =  kwargs[param_key]

        # Token Check
        # result = self.login_session_check_and_update()

        # if not result["status"]:
        #     if response_body.get("logout") == True:
        #         pass
        #     else:
        #         response_body["result"] = None
        #         response_body["message"] = result["message"]
        #         response_body["status"] = 0
        #         response_body["expired"] = True
        # elif result.get("login") == True:
        #     if response_body.get("login") == True:
        #         pass
        #     else :
        #         response_body["result"] = None
        #         response_body["status"] = 0
        #         response_body["expired"] = True
        # else:
        #     if result.get("token") is not None:
        #         response_body["token"] = result["token"]
        
        # if response_body["status"] == 0:
        #     log_access({'username':request.headers.get('Jf-User'), 'header':dict(request.headers), 'ret':response_body})
        response_body["api"] = "2020-06-12"
        return Response(json_encode(response_body), headers=headers, mimetype="application/json")
        # return Response(jsonify(response_body))
        # return jsonify(response_body)
        
send = CustomResource().send