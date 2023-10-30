from django.shortcuts import render
from django.http import HttpResponse, Http404
from django.views.decorators.csrf import ensure_csrf_cookie
from django.core.files.storage import FileSystemStorage
import pickle
import os
from subprocess import Popen, PIPE
import pandas as pd

# Create your views here.
def index(request):
    if request.method=="POST":
        uploaded_file = request.POST['input_file'] # get the uploaded file
        print(uploaded_file)
        result = make_prediction(uploaded_file)
        if result =='no':
            result = 'Benign File'
        else:
            result='Malicious File'
        return render(request, "singlepage/index.html",{'uploaded_file':uploaded_file,'Prediciton':result})
    else:
        return render(request, 'singlepage/index.html')
    

def make_prediction(file):
    loaded_model = pickle.load(open('normalized_data_pred_model.sav', 'rb'))
    # result = loaded_model.score(X_test, y_test)
    if '.pdf' in file:
        command_to_execute_benign = 'python pdfid.py ' + 'Ben01/' + '"' + file + '"'
        stdout = Popen(command_to_execute_benign, shell=True, stdout=PIPE).stdout
        output = stdout.readlines()
        print(output)
    else:
    # mal_file = '00f4989eaf5855226b810c90675c6db89e6dda4ae30eac480885f9fae29bf0ba'
        command_to_execute = 'python pdfid.py ' + 'f1/' + '"' + file + '"'
        stdout = Popen(command_to_execute, shell=True, stdout=PIPE).stdout
        output = stdout.readlines()
    featurename_list = ['obj', 'stream', 'xref', 'startxref', 'Encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction', 'AcroForm', 'JBIG2Decode', 'RichMedia',
            'Launch', 'EmbeddedFile', 'XFA', 'Malicious_Label']
    
    input_list=[]
    input_list.append(ExtractFeatures(output))
    features = featurename_list[:-1]
    in_df = pd.DataFrame(input_list,columns=features)
    print(in_df)
    in_features = in_df.iloc[:, 1: 17]
    result = loaded_model.predict(in_df)
    print(result)
    return result[0]
    
def ExtractFeatures(data):
    features=[]
    #objs count as feature 1
    try:
        objs = data[2]
        objs = (objs.strip().replace(b' ',b'')).decode('UTF-8')
        objs = objs.replace('obj','')
        features.append(int(objs))
    except Exception as e:
        features.append(10)
        pass
    #stream count as feature 2
    try:
        streams = data[4]
        streams = (streams.strip().replace(b' ',b'')).decode('UTF-8')
        streams = streams.replace('stream','')
        features.append(int(streams))
    except Exception as e:
        features.append(10)
        pass
    #xref count as feature 3
    try:
        xrefs = data[6]
        xrefs = (xrefs.strip().replace(b' ',b'')).decode('UTF-8')
        xrefs = xrefs.replace('xref','')
        features.append(int(xrefs))
    except Exception as e:
        features.append(10)
        pass

    #startxref count as feature 4
    try:
        startxrefs = data[8]
        startxrefs = (startxrefs.strip().replace(b' ',b'')).decode('UTF-8')
        startxrefs = startxrefs.replace('startxref','')
        features.append(int(startxrefs))
    except Exception as e:
        features.append(10)
        pass

    #Encrypt count as feature 5
    try:
        encrypts = data[10]
        encrypts = str((encrypts.strip().replace(b' ',b'')).decode('UTF-8'))
        encrypts = encrypts.replace('/Encrypt','')
        features.append(int(encrypts))
    except Exception as e:
        features.append(10)
        pass

    #ObjStreams count as feature 6
    try:
        ObjStms = data[11]
        ObjStms = (ObjStms.strip().replace(b' ',b'')).decode('UTF-8')
        ObjStms = ObjStms.replace('/ObjStm','')
        features.append(int(ObjStms))
    except Exception as e:
        features.append(10)
        pass

    #JS count as feature 7
    try:
        JSs = data[12]
        JSs = (JSs.strip().replace(b' ',b'')).decode('UTF-8')
        JSs = JSs.replace('/JS','')
        features.append(int(JSs))
    except Exception as e:
        features.append(10)
        pass

    #Javascript count as feature 8
    try:
        jScripts = data[13]
        jScripts = (jScripts.strip().replace(b' ',b'')).decode('UTF-8')
        jScripts = jScripts.replace('/JavaScript','')
        features.append(int(jScripts))
    except Exception as e:
        features.append(10)
        pass

    #AA count as feature 9
    try:
        AAs = data[14]
        AAs = (AAs.strip().replace(b' ',b'')).decode('UTF-8')
        AAs = AAs.replace('/AA','')
        features.append(int(AAs))
    except Exception as e:
        features.append(10)
        pass

    #OpenAction count as feature 10
    try:
        openActions = data[15]
        openActions = (openActions.strip().replace(b' ',b'')).decode('UTF-8')
        openActions = openActions.replace('/OpenAction','')
        features.append(int(openActions))
    except Exception as e:
        features.append(10)
        pass

    #AcroForm count as feature 11
    try:
        AcroForms = data[16]
        AcroForms = (AcroForms.strip().replace(b' ',b'')).decode('UTF-8')
        AcroForms = AcroForms.replace('/AcroForm','')
        features.append(int(AcroForms))
    except Exception as e:
        features.append(10)
        pass

    #JBIG2Decode count as feature 12
    try:
        jbig2Decodes = data[17]
        jbig2Decodes = (jbig2Decodes.strip().replace(b' ',b'')).decode('UTF-8')
        jbig2Decodes = jbig2Decodes.replace('/JBIG2Decode','')
        features.append(int(jbig2Decodes))
    except Exception as e:
        features.append(10)
        pass

    #RichMedia count as feature 13
    try:
        RichMedia = data[18]
        RichMedia = (RichMedia.strip().replace(b' ',b'')).decode('UTF-8')
        RichMedia = RichMedia.replace('/RichMedia','')
        features.append(int(RichMedia))
    except Exception as e:
        features.append(10)
        pass

    #Launch count as feature 14
    try:
        launches = data[19]
        launches = (launches.strip().replace(b' ',b'')).decode('UTF-8')
        launches = launches.replace('/Launch','')
        features.append(int(launches))
    except Exception as e:
        features.append(10)
        pass


    #EmbeddedFile count as feature 15
    try:
        efs = data[20]
        efs = (efs.strip().replace(b' ',b'')).decode('UTF-8')
        efs = efs.replace('/EmbeddedFile','')
        features.append(int(efs))
    except Exception as e:
        features.append(10)
        pass

    #XFA count as feature 16
    try:
        xfas = data[20]
        xfas = (xfas.strip().replace(b' ',b'')).decode('UTF-8')
        xfas = xfas.replace('/XFA','')
        features.append(int(efs))
    except Exception as e:
        features.append(10)
        pass
#     features.append(label)
    return features

def feature_extraction(filepath):
    features = []
    command_to_execute = 'python pdfid.py ' + filepath
    stdout = Popen(command_to_execute, shell=True, stdout=PIPE).stdout
    output = stdout.readlines()
    features.append(ExtractFeatures(output))
    return features