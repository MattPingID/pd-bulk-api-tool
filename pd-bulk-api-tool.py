#! /bin/python3

import os.path
import requests
import sys
import time
import json
import re
from sys import argv
from subprocess import call
from getpass import getpass
import tkinter as tk
from tkinter import filedialog

requests.packages.urllib3.disable_warnings() #Disblae invalid cert warnings

options = { 1: 'Add LDAP Entries',
            2: 'Delete LDAP Entries',
            3: 'Modify LDAP Entries',
            4: 'Exit'  }

def main():
    try:
        call('clear' if os.name =='posix' else 'cls') #clear screen

        ## PD API Endpoint:
        pd_api_base_url = "https://localhost:1443/directory/v1/"   # Replace with desired instance URL 
        headers = { 'Content-Type': 'application/json' }
        
        login_credentials = get_ldap_creds()
        
        while(True):
            print_menu()
            menu_selection = ''

            try:
                menu_selection = int(input("\nSelect Option: "))
            except:
                pass

            if (menu_selection == 1):
                print("\n- Select input file containing entries to add.\n- Input file must be either json or raw text consisting of one entery per line enclosed in braces\n\nExample:\n{\"_dn\": \"uid=user.0,ou=people,dc=example,dc=com\",\"objectClass\": [\"top\", \"organizationalPerson\", \"inetOrgPerson\", \"pf-connected-identities\"],\"sn\": [\"Seawell\"],\"cn\": [\"Esko Seawell\"],\"givenName\": [\"Esko\"],\"uid\": [\"user.0\"],\"mail\": [\"user.0@example.com\"],\"userPassword\": [\"2FederateM0re\"],\"pf-connected-identity\": [\"auth-source=pf-local-identity:user-id=user.0\"]}")  
                input_file = select_input_file()
                add_ldap_entries(input_file, pd_api_base_url, headers, login_credentials)
    
            elif (menu_selection == 2):
                print("Select input file containing entries to delete.\nInput file must be raw text consisting of a single DN per line")
                input_file = select_input_file()
                delete_ldap_entries(input_file, pd_api_base_url, headers, login_credentials)
    
            elif(menu_selection == 3):
                pass
    
            elif (menu_selection == 4):
                print("\nExiting")
                exit()
    
            elif (menu_selection not in options.keys()):
                print("Invalid option!\n")

    except KeyboardInterrupt:
        sys.exit(0)

def print_menu():
    print("\n\t\t\t* * * * Menu * * * *\n")
    for key in options.keys():
        print("\t\t",key,"--",options[key]) 

def select_input_file():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    return file_path

def validate_json(input_file):        
    try:
        with open(input_file, 'r') as data:
            json.load(data)
    except ValueError as err:
        return False
    return True

def get_ldap_creds():
    login = "cn=Administrator"
    default_admin_acct = input("Log in with 'cn=Administrator'? (y/n): ")
    
    if (default_admin_acct == 'n') or (default_admin_acct == 'N'):
        login = input("Login: ")    
   
    password = "2FederateM0re" #getpass("Admin Password: ")
    return (login, password)

def add_ldap_entries(input_file, pd_api_base_url, headers, login_credentials):
    try:
        # Process entries
        valid_json = validate_json(input_file)
    
        with open(input_file, 'r') as ldap_entries:
            if (valid_json):
                ldap_data = json.load(ldap_entries)
                data = ldap_data['entries']
            else: 
                data = ldap_entries

            for entry in  data: #ldap_data['entries']: #ldap_data['entries']: #in ldap_entries:
                print("\nAdding entry: {}".format(entry))
                entry = str(entry).replace('\'', '"')
                request_url="{}".format(pd_api_base_url)
                api_response = requests.post(request_url, verify=False, auth=login_credentials, headers=headers, data="{}".format(entry))

                if (api_response.status_code == 201):   
                    print("Response Code: {} - SUCCESS\n".format(api_response.status_code))          
                else:
                    print(api_response.json())
                time.sleep(0.25)    
    except IOError:
        print("Invalid File")

def delete_ldap_entries(input_file, pd_api_base_url, headers, login_credentials):
    ## Process entries
    valid_json = validate_json(input_file)
 
    with open(input_file, 'r') as ldap_entries:
        if (valid_json):
            ldap_data = json.load(ldap_entries)
            data = ldap_data['entries']
        else: 
            data = ldap_entries

        for dn in data:
            
            dn = dn.rstrip('\n')  #remove trailing newline
            print("\nDeleting entry: {}".format(dn.split(',', 1)[0]))  # strip full DN after UID
            request_url="{}{}".format(pd_api_base_url, dn)
            api_response = requests.delete(request_url, headers=headers, verify=False, auth=login_credentials)
    
            if (api_response.status_code == 204):
                print("Response Code: {} - SUCCESS\n".format(api_response.status_code))
            else:
                print(api_response.json())
          
            time.sleep(0.25)

if __name__ == "__main__":
    main()
    
