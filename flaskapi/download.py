#-*- coding: utf-8 -*-
from flask import Flask, render_template, request,send_file,send_from_directory, Response
import datetime
#from werkzeug import secure_filename
import os

app = Flask(__name__)

@app.route('/')
def home_page():
    files = os.listdir('.')
    return render_template('filedown.html')
def download():
    if request.method == 'POST':
        sw=0
        #해당경로가 들어가야함
        files = os.listdir('.')
        
        #파일 or 폴더가 존재하는지 여부 확인해야함
        #없으면 return으로 알리기
        for x in files:
            if(x==request.form['file']):
                sw=1
        now = datetime.datetime.now()
        nowDate = now.strftime('%Y-%m-%d')
        #os.system('cd templates')
        list_test = ' '.join(['a.c','b.c'])
        print(list_test)
        filename= list_test
        #for file_ in list_test :
        #    filename += file_+' '
        zip_name = nowDate+'.tar.gz'
        #os.chdir('./templates/a/b/c')
        os.system('cd ./templates/a/b/c && tar -zcf {} {}'.format(zip_name,filename))
        os.system('ls')
        
        #, attachment_filename = request.form['file'], as_attachment= True)
        return send_from_directory(directory = './templates/a/b/c',filename = '2020-11-11.tar.gz', as_attachment= True)
        #return send_file(request.form['file'], attachment_filename = request.form['file'], as_attachment= True)
@app.route('/filedown', methods =['GET','POST'] )

def post():
    return download()
    

def remove_tar():
    try:
        #.tar파일이 존재하는지 확인
        files=fnmatch.filter(os.listdir(replace_path),'*.tar.gz')
        if files is not None:
            os.system('rm -r *.tar.gz')
        return response(status = 1, message = 'remove success')
    except:
        traceback.print_exc()
        return response(status = 0, message = "remove error")




if __name__ == '__main__':
    app.run(host = '192.168.1.19', port = 5000,debug = True)
