import logging
import subprocess
import argparse
import yaml
def install_package(package_name):
    subprocess.check_call(["sudo","pip3", "install", package_name])

# Install ruamel.yaml
install_package("ruamel.yaml")

# Now you can import and use ruamel.yaml
from ruamel.yaml import YAML
import ruamel.yaml

# Your code using ruamel.yaml here


import os, sys
import time
import paramiko
import requests
import json
import random
import math
from vault import vault
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

cmd = """/bin/bash /home/centos/scripts/get_urls.sh |grep "GRAFANA UI"|head -1|awk -F"==>" '{print $2}'|xargs"""
grafanaurl, error = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                                     shell=True).communicate()
print(grafanaurl)
graf_url = grafanaurl



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


def exeCommand(command):
    logging.debug("\nCommand = " + str(command))
    process = subprocess.Popen(command,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              stdin=subprocess.PIPE, shell=True)
    stdout_bytes, stderr_bytes = process.communicate()
    # Decode bytes-like objects to strings
    stdout_str = stdout_bytes.decode('utf-8')
    stderr_str = stderr_bytes.decode('utf-8')

    return stdout_str, stderr_str


def executeRemoteCommand(command, ssh):
    logging.debug("\n\nCommand = " + str(command))
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.readlines()
    error = stderr.readlines()
    logging.debug("\nOutput = " + str(output))
    logging.debug("\nError = " + str(error))
    return output, error


class commonMethods:
    def __init__(self):
        self.username = vault.yFetch("node", "username", "")
        self.password = vault.yFetch("node", "password", "")

    def create_cronjob(self):
        with open('/home/centos/crontab_lable.txt', 'w') as f:
            f.write("*/5 * * * * python /home/centos/chaos-exp/node_chaos_exp.py -ct 'true'")
        crontab_set_command="crontab /home/centos/crontab_lable.txt"
        output, error = exeCommand(crontab_set_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))

    def fetch_nodes(self):
        logging.info(" ************************************* fetching nodes ************************************* \n")
        node_names_commands = "kubectl get nodes | awk '{print $1}' | tail -n +2"
        output, error = exeCommand(node_names_commands)
        node_names = output.split('\n')
        del node_names[-1]
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        return node_names

    def chaos_installation(self):
        logging.info(
            " ************************************* install chaos operator ************************************* \n")
        install_scheduler = "kubectl apply -f /home/centos/chaos-exp/chaos-operator/litmus-operator-v2.14.0.yaml"
        output, error = exeCommand(install_scheduler)
        logging.info(output)
        logging.error(error)


    def install_crds(self):
        logging.info(
            " ************************************* install chaos scheduler ************************************* \n")
        install_scheduler_rbac = "kubectl apply -f /home/centos/chaos-exp/crds/chaosengine_crd.yaml"

        output, error = exeCommand(install_scheduler_rbac)
        logging.info(output)
        logging.error(error)
        install_schedule_crd = "kubectl apply -f /home/centos/chaos-exp/crds/chaosexperiment_crd.yaml"

        output, error = exeCommand(install_schedule_crd)
        logging.info(output)
        logging.error(error)
        install_scheduler = "kubectl apply -f /home/centos/chaos-exp/crds/chaosresults_crds.yaml"
        output, error = exeCommand(install_scheduler)
        logging.info(output)
        logging.error(error)

    def chaos_scheduler(self):
        logging.info(
            " ************************************* install chaos scheduler ************************************* \n")
        install_scheduler_crd = "kubectl apply -f /home/centos/chaos-exp/chaos-scheduler/chaos-scheduler-2.14.yaml"
        output, error = exeCommand(install_scheduler_crd)
        logging.info(output)
        logging.error(error)

    def install_node_exp(self, exp, path):
        logging.info(" ************************************* node exp ************************************* \n")
        command = path + "/chaos-exp/node-" + exp
        os.chdir(command)
        installation_command = "kubectl apply -f node-" + exp + "-exp.yaml"
        output, error = exeCommand(installation_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        if "restart" in exp:
            command = path + "/chaos-exp/node-" + exp
            os.chdir(command)
            secret_command = "kubectl apply -f secret.yaml"
            output, error = exeCommand(secret_command)
            logging.info("\nOutput = " + str(output))
            logging.error("\nError = " + str(error))



    # print output

    def create_node_exp_sa(self, exp):
        logging.info(" ************************************* install node sa ************************************* \n")
        rbac_command = "kubectl apply -f node-" + exp + "-rbac.yaml"
        output, error = exeCommand(rbac_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))

    # print output

    def create_node_exp_chaosengine(self, exp):
        logging.info(
            " ************************************* install chaos node ce ************************************* \n")
        chaosengine_command = "kubectl apply -f node-" + exp + "-ce.yaml"
        output, error = exeCommand(chaosengine_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))

    # print output

    def create_node_schedule_chaosengine(self, exp, filename, count):
        logging.info(
            " ************************************* install chaos node scheduler ************************************* \n")
        folder_name = "node-" + exp
        command = str(path) + "/chaos-exp/" + str(folder_name)
        os.chdir(command)
        prefixname = "scheduled-engine"
        # suffix_name=folder_name.split("//")[2]
        schedulename = prefixname + "-" + folder_name + str(count)
        with open(filename) as f:
            yaml_values = yaml.safe_load(f)

            yaml_values['metadata']['name'] = schedulename

        with open(filename, "w") as f:
            yaml.dump(yaml_values, f, default_flow_style=False, sort_keys=True)
        command = path + "/chaos-exp/node-" + exp
        os.chdir(command)

        installation_command = "kubectl apply -f " + filename
        output, error = exeCommand(installation_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        # print output

    def find_cpu_hog_nodefetch(self):
        logging.info(
            " ************************************* fetch nodes for cpu hog ************************************* \n")
        fetch_command = "kubectl top nodes | awk '{print $1}' | tail -n +2"
        output, error = exeCommand(fetch_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        nodenames_fetch = output.split('\n')
        del nodenames_fetch[-1]
        cpu_utilization_command = "kubectl top nodes | awk '{print $3}' | tail -n +2"
        output, error = exeCommand(cpu_utilization_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        cpu_utilization = output.split('\n')
        del cpu_utilization[-1]
        cpu_utilization_list = []
        for cpu in cpu_utilization:
            cpu = cpu.strip('%')
            cpu_utilization_list.append(cpu)
        cpu_hog_nodelist = dict(list(zip(nodenames_fetch, cpu_utilization_list)))
        sorted_nodelist = sorted(list(cpu_hog_nodelist.items()), key=lambda x: x[1], reverse=True)
        return sorted_nodelist

    def find_memory_hog_nodefetch(self):
        logging.info(
            " ************************************* fetch nodes for memory hog ************************************* \n")
        fetch_command = "kubectl top nodes | awk '{print $1}' | tail -n +2"
        output, error = exeCommand(fetch_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        nodenames_fetch = output.split('\n')
        del nodenames_fetch[-1]
        memory_utilization_command = "kubectl top nodes | awk '{print $5}' | tail -n +2"
        output, error = exeCommand(memory_utilization_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        memory_utilization = output.split('\n')
        del memory_utilization[-1]
        mem_utilization = []
        for memory in memory_utilization:
            memory = memory.strip('%')
            mem_utilization.append(memory)
        memory_hog_nodelist = dict(list(zip(nodenames_fetch, mem_utilization)))
        sorted_nodelist = sorted(list(memory_hog_nodelist.items()), key=lambda x: x[1], reverse=True)
        return sorted_nodelist

    def find_kubelet_nodefetch(self):
        logging.info(
            " ************************************* fetch nodes for memory hog ************************************* \n")
        # added for kubelet service kill node selection logic to select all nodes in given dc
        dc_list = ["dc-1", "dc-2", "dc-3"]
        selected_dc = random.choice(dc_list)
        txt_file = open("/home/centos/dc.txt", "w")
        txt_file.write(selected_dc)
        txt_file.close()
        fetch_command = "kubectl get nodes --selector='topology.kubernetes.io/zone=" + selected_dc + "'" + "| awk '{print $1}'|tail -n+2"
        output, error = exeCommand(fetch_command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        nodenames_fetch = output.split('\n')
        del nodenames_fetch[-1]
        print(nodenames_fetch)
        glowroot_node = "kubectl get pods -A -o wide|grep glowroot|awk '{print $8}'"
        output, error = exeCommand(glowroot_node)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        glowroot_node = output.split('\n')
        del glowroot_node[-1]
        print(glowroot_node)
        node_names = [x for x in nodenames_fetch if x not in glowroot_node]
        print(node_names)
        return node_names
    def pod_fetch(self):
        cm=commonMethods()
        nodes=cm.find_kubelet_nodefetch()
        podls=[]
        for node in nodes:
            pods="kubectl get pods -ncentos -o wide|grep "+node+" |awk '{print $1}'"
            output, error = exeCommand(pods)
            logging.info("\nOutput = " + str(output))
            logging.error("\nError = " + str(error))
            pods_list = output.split('\n')
            job_list=["curator","kafka-operator","elasticsearch-config","kopf"]
            for pod in pods_list:
                if any(job in pod for job in job_list):
                   pass
                else:
                    label="kubectl label pods "+pod+" apps=chaos -ncentos"
                    output, error = exeCommand(label)
                    print(("\nOutput = " + str(output)))
                    print(("\nError = " + str(error)))
                    logging.info("\nOutput = " + str(output))
                    logging.error("\nError = " + str(error))
            podls.extend(pods_list)
        return podls

    def yaml_changes(self, exp, node, cpu, path, count):
        folder_name = "chaos-exp/node-" + exp
        os.system('ls')
        command = str(path) + "/" + str(folder_name)

        os.chdir(command)
        os.system('ls')
        filename = "scheduled-engine"
        schedulefilename = filename + "-" + exp + "" + str(count) + ".yaml"
        command = "cp " + filename + ".yaml " + schedulefilename
        os.system(command)
        file_type = schedulefilename
        with open(file_type) as f:
            yaml_values = yaml.safe_load(f)

            if exp == 'cpu-hog':
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][0][
                    'value'] = str(cpu)
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][1][
                    'value'] = node
                result = yaml_values['spec']['experiments'][0]['spec']['components']['env']
            elif exp == 'disk-io-stress':
                utilization_percentage = 70
                no_of_workers = len(nodelist)
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][0][
                    'value'] = str(utilization_percentage)
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][1][
                    'value'] = str(cpu)
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][2][
                    'value'] = str(no_of_workers)
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][3][
                    'value'] = node
                result = yaml_values['spec']['experiments'][0]['spec']['components']['env']
            elif exp == 'memory-hog':
                # consumption_mebibites = self.check_memory_avaliable(node)
                # print consumption_mebibites
                consumption_percentage = 100
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][0][
                    'value'] = str(consumption_percentage)
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][1][
                    'value'] = node
                result = yaml_values['spec']['experiments'][0]['spec']['components']['env']
            elif exp == "kubelet-kill-service":
                yaml_values['spec']['experiments'][0]['spec']['components']['env'][0][
                    'value'] = node
                result = yaml_values['spec']['experiments'][0]['spec']['components']['env']
            elif exp == "restart":
                 yaml_values["spec"]["experiments"][0]["spec"]["components"]["env"][1]["value"] = node

            elif exp == "container-service-kill":
                 pass
            elif exp == "network-corruption":
                 pass
            elif exp == "network-latency":
                 pass
            elif exp == "network-loss":
                 pass
            elif exp == "network-partition":
                 pass
            elif exp == "network-duplication":
                 pass

            with open(schedulefilename, "w") as f:
                yaml.dump(yaml_values, f, default_flow_style=False, sort_keys=True)

            filename = "scheduled-engine"
            schedulename = filename + "-" + folder_name + str(count)
            schedulefilename = filename + "-" + exp + "" + str(count) + ".yaml"

            file_type = schedulefilename
            with open(file_type) as f:
                yaml_values = yaml.safe_load(f)
                yaml_values['metadata']['name'] = schedulename
        with open(schedulefilename, "w") as f:
            yaml.dump(yaml_values, f, default_flow_style=False, sort_keys=True)
        print()
        schedulename
        return schedulefilename

    def activate_scheduler(self, exp, count):

        folder_name = "node-" + exp
        command = str(path) + "/chaos-exp/" + str(folder_name)
        os.chdir(command)
        filename = "scheduled-engine"
        schedulename = filename + "-" + folder_name
        schedulefilename = filename + "-" + exp + "" + str(count) + ".yaml"

        file_type = schedulefilename
        with open(file_type) as f:
            yaml_values = yaml.safe_load(f)
        name = yaml_values['metadata']['name']
        command = "kubectl patch chaosschedule " + name + " --type=json -p '[{\"op\":\"replace\",\"path\":\"/spec/scheduleState\",\"value\":\"active\"}]'"
        os.system(command)

    def yaml_data(self):
        os.chdir('..')
        file_type = 'values.yaml'
        with open(file_type) as f:
            yaml_values = yaml.safe_load(f)
            result = yaml_values['services'][1]

    def check_memory_avaliable(self, node):

        fetchnode = " kubectl get nodes -o wide | grep " + node + " | awk '{print $6}'"
        fetchnodename = exeCommand(fetchnode)
        ip = list(fetchnodename)[0].strip('\n')
        print()
        ip

        print()
        self.username
        print()
        self.password
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=self.username, password=self.password)
        from scp import SCPClient, SCPException
        with SCPClient(ssh.get_transport()) as scp:
            os.system('ls')
            scp.put('../calculatemem.sh', '/home/centos/calculatemem.sh')

        memorycommand = "sh calculatemem.sh"
        memory = executeRemoteCommand(memorycommand, ssh)
        print()
        memory
        memory = list(memory)[0]
        print()
        memory
        leftmemory = memory[-1].split(' ')[1].split('\n')[0]
        print()
        leftmemory
        print()
        leftmemory

        total_memory_command = "kubectl describe node " + node + " | grep memory:"
        total_available_memory = exeCommand(total_memory_command)
        print()
        total_available_memory
        total_available_memory = list(total_available_memory)[0].split('\n')[1].split(':')[1].split(' ')[-1].strip('Ki')
        print()
        total_available_memory
        total_available_memory_in_mb = int(total_available_memory) / 1024
        print()
        total_available_memory_in_mb
        mebibytes_to_use = total_available_memory_in_mb - int(leftmemory) - 4096
        # print mebibytes_to_use
        return mebibytes_to_use


class fetchPodStatus:

    def polling_replicas(self):
        cmd = "kubectl get pods -n centos | awk '{print $1}' |  tail -n +2"
        procs = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 stdin=subprocess.PIPE, shell=True).communicate()
        pods = list(procs)[0].strip().split("\n")
        print(pods)
        for pod in pods:
            if 'curator' in pod or 'elasticsearch-config' in pod or 'kafka-operator' in pod:
                continue
            podReadyCommand = "kubectl get pods -n centos " + pod + " | awk '{print $2}' | tail -n +2"
            podStatusCommand = "kubectl get pods -n centos " + pod + " | awk '{print $3}' | tail -n +2"
            print("pod polling...")
            timeout = time.time() + 60 * 30
            result = ""
            while ("Running or Terminating" not in result):
                readyOutput, err1 = subprocess.Popen(podReadyCommand, stdout=subprocess.PIPE,
                                                     stderr=subprocess.PIPE,
                                                     stdin=subprocess.PIPE, shell=True).communicate()
                statusOutput, err2 = subprocess.Popen(podStatusCommand, stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                                                      shell=True).communicate()
                pod_count = readyOutput.split('/')
                print(("pod count is :", pod_count))
                pod_status = str(statusOutput).strip()
                pod_count[1] = pod_count[1].strip()
                # added Terminating state as for kubelet service kill experiment as nodes will be in terminating state for statefulsets forever
                if pod_count[0] == pod_count[1] and pod_status == 'Running' or pod_status == 'Terminating':
                    result = "Running or Terminating"
                    print((pod + " is either running or terminating"))
                time.sleep(10)
                if time.time() > timeout:
                    print("timeout for starting a pod ....  30mins. Time exceeded")
                    exit(1)

    def check_url(self):
        flag = False
        maxWaitCounter = 5
        waitTimeSec = 15
        counter = 0
        resp = None

        centos_ui = graf_url.rsplit("/", 1)[0] + "/system/version "
        token=
        token_headers = {"Authorization": "Bearer " + token + ""}
        sh = requests.session()
        sh.headers.update(token_headers)

        while maxWaitCounter > counter:
            time.sleep(waitTimeSec)
            resp = sh.get(grafanaurl, verify=False)
            logging.info("resp is:" + str(resp))

            if resp.status_code == 200:

                pass
            else:
                print("url not reachable ")
                break
            counter = counter + 1

    def status_of_pods(self):
        command = "kubectl get pods | awk '{print $1}' |  tail -n +2"
        output, error = exeCommand(command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        podsnames = output.split('\n')
        result = self.polling_replicas()

    def run_command(self, cmd):
        """given shell command, returns communication tuple of stdout and stderr"""
        logging.info("run commands : {0}".format(str(cmd)))
        return subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE, shell=True).communicate()

    def chaosengine_phase_status_check(self, chaosengine):
        logging.info("chaosengine polling...")
        count = 0
        timeout = time.time() + 60 * 20  # assuming 20 min timeout for worst case scenario
        status_check = ''
        while ('Completed' not in status_check):
            fetching_phase_of_chaosengine = "kubectl describe chaosresults " + chaosengine + " | grep 'Phase:' "
            fetching_response_of_chaosengine = self.run_command(fetching_phase_of_chaosengine)
            status_check = fetching_response_of_chaosengine[0]
            count = count + 1
            if '' in status_check:
                pass
            time.sleep(60)
            if time.time() > timeout:
                logging.error("timeout waiting for chaosengine .... 20mins Time exceeded")
                break
        verdict_status_check = self.chaosengine_verdict_status_check(chaosengine)
        return verdict_status_check

    def chaosengine_verdict_status_check(self, chaosengine):
        logging.info("chaosengine verdict fetch...")
        count = 0
        timeout = time.time() + 60 * 10  # assuming 10 min timeout for worst case scenario
        verdict_status_check = ''
        while ('Pass' not in verdict_status_check):
            fetching_verdict_of_chaosengine = "kubectl describe chaosresults " + chaosengine + " | grep 'Verdict:' "
            fetching_response_of_chaosengine = self.run_command(fetching_verdict_of_chaosengine)
            verdict_status_check = fetching_response_of_chaosengine[0]
            count = count + 1
            if '' in verdict_status_check:
                pass
            time.sleep(10)
            if time.time() > timeout:
                logging.error("timeout waiting for chaosengine .... 10mins Time exceeded")
                break
        return verdict_status_check

    def check_status(self):
        command = "kubectl get chaosengine | awk '{print $1}' | tail -n +2"
        output, error = exeCommand(command)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        chaosenginelist = output.split('\n')
        del chaosenginelist[-1]
        for chaosengine in chaosenginelist:
            if exp in chaosengine:
                status = self.chaosengine_phase_status_check(chaosengine)
                if 'Pass' in status:
                    print()
                    "experiment completed succesfully "

    def fetch_experiments(self):
        expdict = {}
        fetch_nodes = "kubectl get nodes | awk '{print $1}'| tail -n +2"
        output, error = exeCommand(fetch_nodes)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        nodelist = output.split('\n')
        del nodelist[-1]
        file_type = 'values.yaml'
        with open(file_type) as f:
            yaml_values = yaml.safe_load(f)
            exp = yaml_values['services']
            yaml_values['services'][0]['global_target']['nodes'] = nodelist
            with open(file_type, 'w') as yaml_file:
                yaml_file.write(yaml.dump(yaml_values))
            for expitem in exp:
                if list(expitem.keys())[0] == 'global_target':
                    continue
                else:
                    expdict = dict(list(expdict.items()) + list(expitem.items()))
            return expdict


def execute_query_grafana(graf_url, node_names, mode):
    # Executes the query in grafana
    #:Input : ex_query_params: dictionary of required inputs
    #:Output: executed query response

    # sh = open_session(graf_url, user_name="superuser@k8s.local", password="EnTeRteR")

    # create_session_sso(masterip_derived)
    # print "MASTER VM IP : ",masterip_derived
    try:
        masterip = graf_url.split("/")[2]
    except Exception as e:
        print(graf_url)
        print(e)
        sys.exit(1)

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
        host_label = None
        query = 'sum(kube_node_status_condition{condition="Ready",status!="true"})'
    elif mode == "network-corruption":
        host_label= None
        query= 'sum (rate (container_network_receive_bytes_total{image!=""}[5m])) by (container, pod)/100'
    elif mode == "network-loss":
        host_label=None
        query = 'sum (rate (container_network_receive_bytes_total{image!=""}[5m])) by (container, pod)/100'
    elif mode == "network-duplication":
        host_label=None
        query = 'sum (rate (container_network_receive_bytes_total{image!=""}[5m])) by (container, pod)/100'
    elif mode == "network-latency":
        host_label=None
        query = 'sum (rate (container_network_receive_bytes_total{image!=""}[5m])) by (container, pod)/100'
    elif mode == "network-partition":
        host_label=None
        query = 'sum (rate (container_network_receive_bytes_total{image!=""}[5m])) by (container, pod)/100'


    login_result = sh.get(url + url1, verify=False, params={'query': query})
    resp = build_responsedict(login_result, 'true')
    listr = resp.get('body').get('data').get('result')
    for post_chaos in listr:
        for node_name in node_names:
            if post_chaos.get('metric').get(host_label) == node_name[0]:
                print((node_name[0]))
                logging.info(node_name[0])
                print((int(float(post_chaos.get('value')[1]))))
                logging.info(int(float(post_chaos.get('value')[1])))
                if int(float(post_chaos.get('value')[1])) > threshold:
                    print("chaos started")
                    logging.info("chaos_started")
                else:
                    print("chaos not started")
                    logging.info("chaos not started")
            else:
                if mode == "kubelet-kill-service":
                    if int(float(post_chaos.get('value')[1])) > 0:
                        print("chaos_started")

                        fetch_pod_status = fetchPodStatus()
                        fetch_pod_status.status_of_pods()
                        time.sleep(600)
                        fetch_pod_status.check_url()

                    else:
                        print("chaos not started")
                else:
                    pass

def crontab_label():
    with open("/home/centos/dc.txt","r") as text_file:
       selected_dc=text_file.read().rstrip()
    fetch_command = "kubectl get nodes --selector='topology.kubernetes.io/zone=" + selected_dc + "'" + "| awk '{print $1}'|tail -n+2"
    output, error = exeCommand(fetch_command)
    logging.info("\nOutput = " + str(output))
    logging.error("\nError = " + str(error))
    nodenames_fetch = output.split('\n')
    del nodenames_fetch[-1]
    print(nodenames_fetch)
    glowroot_node = "kubectl get pods -A -o wide|grep glowroot|awk '{print $8}'"
    output, error = exeCommand(glowroot_node)
    logging.info("\nOutput = " + str(output))
    logging.error("\nError = " + str(error))
    glowroot_node = output.split('\n')
    del glowroot_node[-1]
    print(glowroot_node)
    node_names = [x for x in nodenames_fetch if x not in glowroot_node]
    print(node_names)
    for node in node_names:
        pods="kubectl get pods -ncentos -o wide|grep "+node+" |awk '{print $1}'"
        output, error = exeCommand(pods)
        logging.info("\nOutput = " + str(output))
        logging.error("\nError = " + str(error))
        pods_list = output.split('\n')
        job_list=["curator","kafka-operator","elasticsearch-config","kopf"]
        for pod in pods_list:
            if any(job in pod for job in job_list):
               pass
            else:
                 label="kubectl label pods "+pod+" apps=chaos -ncentos"
                 output, error = exeCommand(label)
                 print(("\nOutput = " + str(output)))
                 print(("\nError = " + str(error)))
                 logging.info("\nOutput = " + str(output))
                 logging.error("\nError = " + str(error))

def generate_ssh_key():
    # Generate the id_rsa key using ssh-keygen command
    subprocess.Popen(['ssh-keygen', '-t', 'rsa', '-b', '4096', '-N', '', '-f', 'id_rsa'],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(input=b'\n')
def get_ssh_key_string():
    # Read the contents of the id_rsa.pub file
    with open('/home/centos/.ssh/id_rsa', 'r') as file:
        return file.read().strip()
def update_secrets_yaml(ssh_key_string,exp,path):
    # Load the existing secrets.yaml file
    yaml = YAML()
    with open(path + "/chaos-exp/node-" + exp + "/secret.yaml", 'r') as file:
        secrets = yaml.load(file)

    # Update the ssh-privatekey field with the generated key
    secrets['stringData']['ssh-privatekey'] = ruamel.yaml.scalarstring.PreservedScalarString(ssh_key_string)

    # Write the updated secret.yaml file
    with open(path + "/chaos-exp/node-" + exp + "/secret.yaml", 'w') as file:
        yaml.dump(secrets, file)

def copy_id_rsa_to_ips(ip):
    # Create a new SSH client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        key_path="~/.ssh/id_rsa"
        # Connect to the remote server
        username = vault.yFetch("node", "username", "")
        password = vault.yFetch("node", "password", "")
        client.connect(ip, username=username, password=password)

        command = 'chmod 600 .ssh/authorized_keys'
        _, stdout, stderr = client.exec_command(command)
        command = 'chmod 600 .ssh/id_rsa'
        _, stdout, stderr = client.exec_command(command)
        command = 'chmod 600 .ssh/id_rsa.pub'
        _, stdout, stderr = client.exec_command(command)

        # Run the ssh-copy-id command
        command = 'ssh-copy-id -i {}'.format(key_path)
        _, stdout, stderr = client.exec_command(command)

        # Check the result
        if stdout.channel.recv_exit_status() == 0:
            print("SSH key copied successfully!")
            logging.info("SSH key copied successfully!")
        else:
            print("Failed to copy SSH key.")
            print("Error:", stderr.read().decode().strip())
            logging.error("Failed to copy SSH key.")
            error_message = stderr.read().decode().strip()
            logging.error("Error: %s %s", error_message, ip)
    finally:
        # Close the SSH client connection
        client.close()

if __name__ == '__main__':

    logging.basicConfig(filename="node-chaos-error.log", format='%(asctime)s %(message)s', level=logging.ERROR)
    logging.basicConfig(filename="node-chaos-info.log", format='%(asctime)s %(message)s', level=logging.INFO)
    parser = argparse.ArgumentParser()

    parser.add_argument('-cpu', '--cpu', dest='cpu', default=4, help='no. of cpu u want the exp to utilize')
    parser.add_argument('-fetch', '--fetchnode', dest='fetchnode', default="false", help='fetch nodes randomly')
    # parser.add_argument('-d', '--duration', dest='duration', default=600, help='duration of the exp')
    parser.add_argument('-n', '--nodecount', dest='nodecount', default=5,
                        help='number of nodes to perform chaos experiment')
    parser.add_argument('-e', '--experiment', dest='experiment', default='',
                        help='mention the experiment which u want to perform')
    parser.add_argument('-ct', '--crontab', dest='crontab', default='false',
                        help='put value as true when want to set crontab for apps=chaos label')

    args = parser.parse_args()
    cpu = args.cpu
    fetchnode = args.fetchnode
    # duration = args.duration
    nodecount = args.nodecount
    experiment = args.experiment
    crontab = args.crontab
    global path
    fetch_path = 'pwd'
    output = exeCommand(fetch_path)
    path = output[0]
    print(path)
    path = path.split('\n')[0]
    print()
    path
    if crontab == 'true':
        crontab_label()
        sys.exit(1)
    else:
        pass
    explist = []
    if experiment == '':
        fetch_pod_status = fetchPodStatus()
        experiment_list = fetch_pod_status.fetch_experiments()
        for exp in experiment_list:
            for status in experiment_list[exp]:
                if experiment_list[exp][status] == 'true':
                    explist.append(exp)
    else:
        explist.append(experiment)

    print(explist)
    common_method = commonMethods()
    count = 1
    print()
    "installing chaos operator"
    common_method.chaos_installation()
    # common_method.install_crds()
    common_method.chaos_scheduler()
    nodelist = common_method.fetch_nodes()
    for exp in explist:
        while count <= int(nodecount):
            if fetchnode == 'false':
                if 'cpu-hog' in exp:
                    nodelist = common_method.find_cpu_hog_nodefetch()
                    print(nodelist)
                    node = nodelist[count][0]
                elif 'memory-hog' in exp:
                    nodelist = common_method.find_memory_hog_nodefetch()
                    print(nodelist)
                    node = nodelist[count][0]
                elif 'disk-io-stress' in exp:
                    nodelist = common_method.find_memory_hog_nodefetch()
                    print(nodelist)
                    node = nodelist[count][0]
                elif "restart" in exp:
                    nodelist = common_method.find_memory_hog_nodefetch()
                    print(nodelist)
                    node = nodelist[count][0]
                    # Generate the id_rsa key
                    generate_ssh_key()
                    # Get the SSH key string
                    ssh_key_string = get_ssh_key_string()
                    # Update the secrets.yaml file
                    update_secrets_yaml(ssh_key_string,exp,path)
                    command="kubectl get nodes "+node+" -o jsonpath='{.status.addresses[?(@.type==\"InternalIP\")].address}'"
                    output, error = exeCommand(command)
                    ip=str(output)
                    logging.error("ip to which id _rsa is copied %s", ip)
                    logging.info("\nOutput = " + str(output))
                    logging.error("\nError = " + str(error))
                    # Copy the id_rsa file to the specified IP addresses
                    copy_id_rsa_to_ips(ip)

                elif "kubelet-kill-service" in exp:
                    nodelist = common_method.find_kubelet_nodefetch()
                    print(nodelist)
                    node = nodelist
                    print(node)
                    for i, n in enumerate(node):
                        i = i + 1
                        filename = common_method.yaml_changes(exp, n, cpu, path, i)
                        common_method.install_node_exp(exp, path)
                        common_method.create_node_exp_sa(exp)
                        common_method.create_node_schedule_chaosengine(exp, filename, i)

                    break
                elif "container-service-kill" in exp:
                     node=common_method.pod_fetch()
                     filename = common_method.yaml_changes(exp, node, cpu, path, 2)
                     common_method.install_node_exp(exp, path)
                     common_method.create_node_exp_sa(exp)
                     common_method.create_node_schedule_chaosengine(exp, filename,1)
                     common_method.create_cronjob()
                     break
                elif "network-partition" in exp:
                    node = common_method.pod_fetch()
                    filename = common_method.yaml_changes(exp, node, cpu, path, 2)
                    common_method.install_node_exp(exp, path)
                    common_method.create_node_exp_sa(exp)
                    common_method.create_node_schedule_chaosengine(exp, filename, 1)
                    break
                elif "network-corruption" in exp:
                    node = common_method.pod_fetch()
                    filename = common_method.yaml_changes(exp, node, cpu, path, 1)
                    common_method.install_node_exp(exp, path)
                    common_method.create_node_exp_sa(exp)
                    common_method.create_node_schedule_chaosengine(exp, filename, 1)
                    break
                elif "network-duplication" in exp:
                    node = common_method.pod_fetch()
                    filename = common_method.yaml_changes(exp, node, cpu, path, 1)
                    common_method.install_node_exp(exp, path)
                    common_method.create_node_exp_sa(exp)
                    common_method.create_node_schedule_chaosengine(exp, filename,1)
                    break
                elif "network-loss" in exp:
                    node= common_method.pod_fetch()
                    filename = common_method.yaml_changes(exp, node, cpu, path, 1)
                    common_method.install_node_exp(exp, path)
                    common_method.create_node_exp_sa(exp)
                    common_method.create_node_schedule_chaosengine(exp, filename, 1)
                    break
                elif "network-latency" in exp:
                    node = common_method.pod_fetch()
                    filename = common_method.yaml_changes(exp, node, cpu, path, 1)
                    common_method.install_node_exp(exp, path)
                    common_method.create_node_exp_sa(exp)
                    common_method.create_node_schedule_chaosengine(exp, filename, 1)
                    break
                else:
                    nodelist = nodelist
                    print(nodelist)
                    node = nodelist[count][0]
            else:
                nodelist = nodelist
                node = nodelist[count][0]
            filename = common_method.yaml_changes(exp, node, cpu, path, count)
            if count == 1:
                common_method.install_node_exp(exp, path)
                common_method.create_node_exp_sa(exp)
            common_method.create_node_schedule_chaosengine(exp, filename, count)
            count = count + 1

    time.sleep(300)
    for exp in explist:
        if 'cpu-hog' in exp:
            execute_query_grafana(graf_url, nodelist, 'cpu-hog')
        elif 'memory-hog' in exp:
            execute_query_grafana(graf_url, nodelist, 'memory-hog')
        elif "disk-io-stress" in exp:
            execute_query_grafana(graf_url, nodelist, "disk-io-stress")
        elif "kubelet-kill-service" in exp:
            execute_query_grafana(graf_url, nodelist, "kubelet-kill-service")
        elif "network-corruption" in exp:
            execute_query_grafana(graf_url, nodelist,"network-corruption")
        elif "network-duplication" in exp:
            execute_query_grafana(graf_url, nodelist,"network-duplication")
        elif "network-partition" in exp:
            execute_query_grafana(graf_url, nodelist,"network-partition")
        elif "network-loss" in exp:
            execute_query_grafana(graf_url, nodelist,"network-loss")
        elif "network-latency":
            execute_query_grafana(graf_url, nodelist,"network-latency")
