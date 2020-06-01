import json
import os
import requests

from azure.cosmos import CosmosClient
from datetime import datetime, timedelta
from pathlib import Path


####################
# GLOBAL VARIABLES #
####################

##########################################################################
#
# Function name: main
# Input: None.
# Output: TBD
#
# Purpose: Connect to COSMOS DB and compute delta of malicious URLs
#
##########################################################################
def main():

    print ("**** GET DUMMY RESULTS ****")   
    
    dummy_results = get_netcraft_results()

    filtered_results = filter_netcraft_results(dummy_results)

    date_str = write_results_to_cosmos_db(filtered_results)

    write_attack_urls_to_output(filtered_results, date_str)

##########################################################################
#
# Function name: get_netcraft_results
# Input: TBD
# Output: TBD
#
# Purpose: connect to Netcraft and get all results in Karen Dummy area.
#          These results will include redirects.
#
##########################################################################
def get_netcraft_results():
    print ("**** GET ALL NETCRAFT RESULTS ****")

    net_usrnm = os.environ.get('NETCRAFT_USER')
    net_pswd  = os.environ.get('NETCRAFT_PSWD')

    netcraft = requests.Session()
    netcraft.auth = (net_usrnm, net_pswd)

    url = 'https://takedown.netcraft.com/apis/get-info.php'

    today_date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    yesterday_date_str = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')

    query = {
        'date_from': yesterday_date_str,
        'date_to': today_date_str,
        'region': 'karen_submissions'
    }
 
    print (query)

    r_post = netcraft.post(url=url, data=query)

    netcraft_request_results = {}

    if r_post.status_code == 200:
        netcraft_request_results = r_post.json()

    return netcraft_request_results


##########################################################################
#
# Function name: filter_netcraft_results
# Input: TBD
# Output: TBD
#
# Purpose: TBD
#
##########################################################################
def filter_netcraft_results(netcraft_results):

    print ("**** FILTER NETCRAFT RESULTS ****")

    filtered_netcraft_results = {}

    for record in netcraft_results:
        hostname = record['hostname']
        attack_url = record['attack_url']
        target_brand = record['target_brand']
        attack_type = record['attack_type']
        status = record['status']

        filtered_netcraft_results[attack_url] = {'hostname': hostname, 'target_brand': target_brand, 'attack_type': attack_type, 'status': status}


    for k,v in filtered_netcraft_results.items():
        print (k,v)

    return filtered_netcraft_results



##########################################################################
#
# Function name: write_results_to_cosmos_db
# Input: TBD
# Output: TBD
#
# Purpose: TBD
#
##########################################################################
def write_results_to_cosmos_db(filtered_results):
    print ("**** WRITE RESULTS TO COSMOS DB ****")

    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('DUMMY_CONTAINER_ID')

    client = CosmosClient(uri, {'masterKey': key})
    print (client)

    database = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    # Get date
    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    id_date  = int((datetime.utcnow()).timestamp())
    id_date_str = str(id_date)

    # key = attack_url
    # values = hostname, target_brand, attack_type, status

    output = []

    for k,v in filtered_results.items():
        output.append({'attack_url':k , 'hostname': v['hostname'], 'target_brand': v['target_brand'], 'attack_type': v['attack_type'], 'status': v['status']})

    container.upsert_item( { 'id': id_date_str,
                             'date_time': id_date_str,
                             'date': date_str,
                             'netcraft_results': output })

    return date_str

##########################################################################
#
# Function name: write_attack_urls_to_output
# Input: TBD
# Output: TBD
#
# Purpose: TBD
#
##########################################################################
def write_attack_urls_to_output(filtered_results, date_str):
    print ("**** WRITE LIST OF ATTACK URLS TO OUTPUT ****")

    output_filename = "Attack_URL_List_ALL_" + (date_str.replace(':','-')).replace(' ','_')
    output_filepath = Path('/output') / output_filename
    print (output_filename)
    print (output_filepath)

    url_list = []

    for k,v in filtered_results.items():
        url_list.append(k)

    unique_url_list = list(set(url_list))

    with open(output_filepath, 'w') as output_fh:
        for url in unique_url_list:
            output_fh.write('%s\n' % url)

if __name__ == "__main__":
    main()
