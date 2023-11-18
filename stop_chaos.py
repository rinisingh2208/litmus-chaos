import subprocess
import logging
import json
import argparse
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import time
cmd = """cat /home/atom/docker/kubernetes/atom-deployment/atom.log |grep "GRAFANA UI"|head -1|awk -F"==>" '{print $2}'|xargs"""
grafanaurl, error = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                                     shell=True).communicate()
print(grafanaurl)
graf_url = grafanaurl


def generateKeycloakToken(master_ip):
    mastervmip = master_ip
    # master_ip = mastervmip.split("app.")[1].split(".nip")[0]
    if master_ip.__contains__("/"):
        master_ip = mastervmip.split("/")[2]  # .split(":")[0]
    else:
        master_ip = mastervmip
    # master_ip = mastervmip.split("/")[2]#.split(":")[0]
    user_name = 'admin'
    pass_word = 'Secret@123'
    retry_strategy = Retry(
        total=20,
        backoff_factor=15,
        status_forcelist=[429, 500, 502, 503, 504],
        method_whitelist=["HEAD", "GET", "OPTIONS", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)
    # url_1 = "https://app."+master_ip+".nip.io:32443/auth/realms/master/protocol/openid-connect/token"
    # url_1 = "https://"+master_ip+":32443/auth/realms/master/protocol/openid-connect/token"
    url_1 = "https://" + master_ip + "/auth/realms/master/protocol/openid-connect/token"
    print()
    "URL_1 : ", url_1
    headers_1 = {'Content-Type': 'application/x-www-form-urlencoded'}
    data_1 = 'grant_type=password&username=' + user_name + '&password=' + pass_word + '&client_id=admin-cli'
    response = http.post(url_1, headers=headers_1, data=data_1, verify=False)
    response_1 = json.loads(response.text)
    access_token_1 = response_1['access_token']
    retry_strategy = Retry(
        total=20,
        backoff_factor=15,
        status_forcelist=[429, 500, 502, 503, 504],
        method_whitelist=["HEAD", "GET", "OPTIONS", "POST"]

    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)
    #   print access_token_1

    # url_2 = "https://app."+master_ip+".nip.io:32443/auth/admin/realms/system/clients"
    # url_2 = "https://"+master_ip+":32443/auth/admin/realms/system/clients"
    url_2 = "https://" + master_ip + "/auth/admin/realms/system/clients"
    headers_2 = {'Content-Type': 'application/json', 'Authorization': str('Bearer ' + access_token_1 + '')}
    #   print headers_2
    response_2 = http.get(url_2, headers=headers_2, verify=False)
    response_3 = json.loads(response_2.text)
    #   print response_3
    for items in response_3:
        if items.get('name') == 'atom':
            print()
            "Name : ", items.get('name'), "\tID : ", items.get('id'), "\n"
            atom_client_id = items.get('id')
            break
    #   print atom_client_id
    retry_strategy = Retry(
        total=20,
        backoff_factor=15,
        status_forcelist=[429, 500, 502, 503, 504],
        method_whitelist=["HEAD", "GET", "OPTIONS", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)
    # url_3 = "https://app."+master_ip+".nip.io:32443/auth/admin/realms/system/clients/"+atom_client_id+"/client-secret"
    # url_3 = "https://"+master_ip+":32443/auth/admin/realms/system/clients/"+atom_client_id+"/client-secret"
    url_3 = "https://" + master_ip + "/auth/admin/realms/system/clients/" + atom_client_id + "/client-secret"
    headers_3 = {'Content-Type': 'application/json', 'Authorization': str('Bearer ' + access_token_1 + '')}
    #   print headers_3
    response_4 = http.get(url_3, headers=headers_3, verify=False)
    response_5 = json.loads(response_4.text)
    client_secret = response_5['value']
    #   print client_secret
    retry_strategy = Retry(
        total=20,
        backoff_factor=15,
        status_forcelist=[429, 500, 502, 503, 504],
        method_whitelist=["HEAD", "GET", "OPTIONS", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)
    # url_4 = 'https://app.'+master_ip+'.nip.io:32443/auth/realms/system/protocol/openid-connect/token'
    # url_4 = 'https://'+master_ip+':32443/auth/realms/system/protocol/openid-connect/token'
    url_4 = 'https://' + master_ip + '/auth/realms/system/protocol/openid-connect/token'
    headers_4 = {'Content-Type': 'application/x-www-form-urlencoded'}
    data_4 = 'client_id=atom&grant_type=password&client_secret=' + client_secret + '&scope=openid&username=' + user_name + '&password=' + pass_word + ''
    #   print data_4
    response_6 = http.post(url_4, headers=headers_4, data=data_4, verify=False)
    response_7 = json.loads(response_6.text)
    keycloak_id_token = response_7['id_token']
    print()
    "KEYCLOAK ID TOKEN : ", keycloak_id_token
    return keycloak_id_token


def convert(input):
    if isinstance(input, dict):
        new_dict = {}
        for k, v in input.items():
            new_dict[convert(k)] = convert(v)
        return new_dict
    elif isinstance(input, list):
        new_list = []
        for element in input:
            new_list.append(convert(element))
        return new_list
    elif isinstance(input, str):
        return input.encode('utf-8')
    else:
        return input


def build_responsedict(response, bLoadBody):
    responseDict = {}
    responseDict['status'] = response.status_code
    responseDict['reason'] = response.reason
    responseDict['body'] = None
    if bLoadBody == 'true':
        try:
            if type(response.text) == dict:
                responseDict['body'] = response.text
            else:
                responseDict['body'] = response.json()
        except Exception as e:
            responseDict['body'] = None
            logging.debug("Response body None " + str(e))
            logging.debug("response " + str(response.text))
    responseDict = convert(responseDict)
    return responseDict


def executeCommand(command):
    output = []
    print(("\nCommand = " + str(command)))
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        output.append(line)
        print((line.rstrip()))
    return output


def execute_query_grafana(node_names, mode):
    # Executes the query in grafana
    #:Input : ex_query_params: dictionary of required inputs
    #:Output: executed query response

    # sh = open_session(graf_url, user_name="superuser@k8s.local", password="EnTeRteR")

    # create_session_sso(masterip_derived)
    # print "MASTER VM IP : ",masterip_derived
    masterip = graf_url.split("/")[2]
    keycloak_id_token = generateKeycloakToken(masterip)
    print()
    "KEYCLOAK ID TOKEN : ", keycloak_id_token

    url = graf_url
    url = url.strip()
    logging.info("url : " + str(url))
    token_headers = {"Authorization": "Bearer " + keycloak_id_token + ""}
    sh = requests.session()
    sh.headers.update(token_headers)
    url1 = "/api/datasources/proxy/1/api/v1/query"
    if mode == "cpu-hog":
        query = 'topk(5, sum (rate (container_cpu_usage_seconds_total{id="/"}[3m])) by (kubernetes_io_hostname) / sum( label_replace(kube_node_status_capacity{resource="cpu"}, "kubernetes_io_hostname", "$1", "node", "(.*)")) by (kubernetes_io_hostname) *100)'
        host_label = "kubernetes_io_hostname"
        threshold = 75
    elif mode == "memory-hog":
        query = 'topk(5, sum(((node_memory_MemTotal_bytes{kubernetes_node!=""} - node_memory_MemAvailable_bytes)/node_memory_MemTotal_bytes) * 100) by(kubernetes_node))'
        host_label = "kubernetes_node"
        threshold = 75
    elif mode == "disk-io-stress":
        query = '(1-(node_filesystem_free_bytes{fstype=~"ext4|xfs"} / node_filesystem_size_bytes{fstype=~"ext4|xfs"})) * 100'
        host_label = "kubernetes_node"
        threshold = 25
    elif mode == "kubelet-kill-service":
        host_label=None
        query='sum(kube_node_status_condition{condition="Ready",status!="true"})'
    login_result = sh.get(url + url1, verify=False, params={'query': query})
    resp = build_responsedict(login_result, 'true')
    listr = resp.get('body').get('data').get('result')
    for post_chaos in listr:
        if post_chaos.get('metric').get(host_label) in node_names:
            print("")
            logging.info(post_chaos.get('metric').get(host_label))
            print((post_chaos.get('metric').get(host_label)))
            print((int(float(post_chaos.get('value')[1]))))

            if int(float(post_chaos.get('value')[1])) > threshold:
                print("chaos running")
                logging.info("chaos running")
            else:

                print("chaos not running")
                logging.info("chaos not running")
        else:
            if mode == "kubelet-kill-service":
                if int(float(post_chaos.get('value')[1])) > 0:
                    print("chaos_started")
                else:
                    print("chaos not started")
            else:
                pass

def exeCommand(command):
    logging.debug("\nCommand = " + str(command))
    result = subprocess.Popen(command,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              stdin=subprocess.PIPE, shell=True).communicate()
    return result


def fetch_nodes():
    logging.info(" ************************************* fetching nodes ************************************* \n")
    node_names_commands = "kubectl get nodes | awk '{print $1}' | tail -n +2"
    output, error = exeCommand(node_names_commands)
    node_names = output.split('\n')
    del node_names[-1]
    logging.info("\nOutput = " + str(output))
    logging.error("\nError = " + str(error))
    return node_names


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--experiment', dest='experiment', default='',
                        help='mention the experiment which u want to perform')
    args = parser.parse_args()
    experiment = args.experiment
    command1 = "kubectl get chaosengine | awk '{print $1}' | tail -n +2"
    chaosengine = executeCommand(command1)
    print(chaosengine)
    chaosenginelist = list(chaosengine)
    print(chaosenginelist)
    command2 = "kubectl get chaosschedule | awk '{print $1}' | tail -n +2"
    chaosschedule = executeCommand(command2)
    print(chaosschedule)
    chaosschedulelist = list(chaosschedule)
    print(chaosschedulelist)
    for chaos in chaosenginelist:
        chaos = chaos.strip('\n')
        print(chaos)

        command = "kubectl patch chaosengine " + chaos + " --type=json -p '[{\"op\":\"replace\",\"path\":\"/spec/engineState\",\"value\":\"stop\"}]'"
        print(command)
        chaosenginelist = executeCommand(command)
        # deleting chaosengine for experiment
        command1 = "kubectl delete chaosengine " + chaos
        print(command1)
        chaosenginelist = executeCommand(command1)
    for chaos in chaosschedulelist:
        chaos = chaos.strip('\n')
        print(chaos)

        command = "kubectl patch chaosschedule " + chaos + " --type=json -p '[{\"op\":\"replace\",\"path\":\"/spec/scheduleState\",\"value\":\"stop\"}]'"
        print(command)
        chaosschedulelist = executeCommand(command)
        # deleting chaosengine for experiment
        command1 = "kubectl delete chaosschedule " + chaos
        print(command1)
        chaosschedulelist = executeCommand(command1)
    print("unlabelling pods")
    command="kubectl label pods --all -natom apps-"
    print(command)
    chaosschedulelist = executeCommand(command)
    command1="sudo crontab -r"
    print(command1)
    chaosschedulelist = executeCommand(command1)
    time.sleep(300)
    nodelist = fetch_nodes()

    if 'cpu-hog' in experiment:
        execute_query_grafana(nodelist, 'cpu-hog')
    elif 'memory-hog' in experiment:
        execute_query_grafana(nodelist, 'memory-hog')
    elif "disk-io-stress" in experiment:
        execute_query_grafana(nodelist, "disk-io-stress")
    elif "kubelet-kill-service" in experiment:
        execute_query_grafana(nodelist, "kubelet-kill-service")