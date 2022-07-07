#!/usr/bin/env python
import json
from huepy import *
import os
from os import path
import requests
import sys
import time
import hashlib
import csv


if "VTSCAN_API_KEY" in os.environ:
    api_key=os.environ.get("VTSCAN_API_KEY") #export VTSCAN_API_KEY=YOURAPIKEY or pass it with "-k" flag
else:
    api_key="1c960c1d3a9020d8184f7a375c4316eff29e77405921fbdee335255c104a31e4"

def check_response_code(resp):
    print(resp.status_code)
    if resp.status_code == 204:
        print(bad("Request rate limit exceeded"))
        sys.exit()

#获取文件的hash值
def get_hash256(filename):
    with open(filename, 'rb') as fp:
        data = fp.read()
    # 使用 md5 算法
    file_md5 = hashlib.sha256(data).hexdigest()
    return file_md5


##获取文件的大小
def get_size(filename):
    fsize = os.path.getsize(filename)
    fsize = fsize / float(1024 * 1024)
    return fsize

#上传文件
"""
根据v3版本的api的规范，大于32MB的文件需要独立申请API，所以需要url参数
delay是为了根据不同的文件大小而进行等待
返回的resp是为了判断上传是否成功
"""
def upload(url,headers,filename,delay):
    print(filename, "is uploading")
    file = {"file": open(filename, 'rb')}
    resp = requests.post(url, files=file, headers=headers)
    print(filename,"upload successfully")
    time.sleep(delay)
    return resp

"""
data是需要写入的数据
write_data函数以a的方式每次在末尾增加一条信息
"""
def write_data(data):
    with open('data.csv', 'a', encoding='utf-8', newline='') as fp:
        writer = csv.writer(fp)
        writer.writerow(data)


def main():


    folder = "F:\\apks"
    DetectedFiles = os.listdir(folder)

    #csv文件的初始化
    # header是csv文件各列名
    header = ['apk_name', 'hash', 'tag']

    with open('data.csv', 'a', encoding='utf-8', newline='') as fp:
        # 写入
        writer = csv.writer(fp)
        # 设置标题
        writer.writerow(header)

    print("---------------------------------------------------------\n\n")
    #开始遍历文件
    for file in DetectedFiles:
        #拼接为绝对路径
        file = path.join(folder, file)
        #上传的headers都是一致的
        headers = {
            "Accept": "application/json",
            "x-apikey": api_key
        }
        # 使用V3版本上传文件
        # 首先去判断文件大小
        #计算文件大小
        fsize = get_size(file)
        if fsize <= 32:
            url = "https://www.virustotal.com/api/v3/files"
            delay = 15
            resp = upload(url,headers,file,delay)
            #等待，上传小文件的时间是15s，这里等待15s

            #判断上传是否成功
            if(resp.status_code == 200):
                print(file,"uploaded successfully")
            #上传失败只进行单次等待，减少运行时间
            elif(resp.status_code == 400):
                #延长等待时间
                delay *=2
                resp = upload(url,headers,file,delay)

        #文件大小为32MB--500MB单独申请一次性上传连接
        elif fsize <= 500:
            url = "https://www.virustotal.com/api/v3/files/upload_url"
            resp = requests.get(url, headers=headers)
            #读取与返回的.json文件
            url = resp.json()["data"]
            #设置大文件的delay,+5是缓冲时间
            delay = fsize/1+5;
            upload(url,headers,file,delay)
        else :
            print("The",file,"exceeds the upload size limit!")
            continue

        """
            接下来的部分是读取检测后的报告
        """
        #根据md5值查询检测报告
        report_url = "https://www.virustotal.com/api/v3/files/"
        report_url += get_hash256(file)

        resp = requests.get(report_url, headers=headers)

        #接下来是输出resp的结果
        print("[*] Received response\n")
        resp_json = json.loads(resp.text)
        print("----------------------获取检测报告---------------------\n")
        print(file)
        tag = 0
        if (resp_json["data"]["attributes"]["total_votes"]["harmless"] + resp_json["data"]["attributes"]["total_votes"][
            "malicious"] > 0):
            tag = 1
        data = [file, get_hash256(file), tag]
        write_data(data)
        print("----------------------检测报告获取完毕---------------------\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
