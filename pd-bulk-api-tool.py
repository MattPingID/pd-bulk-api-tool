#! /bin/python3

import os.path
import requests
import sys
import time
import json
import tkinter as tk
from tkinter import filedialog
from subprocess import call
from getpass import getpass


requests.packages.urllib3.disable_warnings() #Disblae invalid cert warnings

options = { 1: 'Add LDAP Entries',
            2: 'Delete LDAP Entries',
            3: 'Modify LDAP Entries',
            4: 'Exit'  }

def main():
    try:
        call('clear' if os.name =='posix' else 'cls') #clear screen

        print("\n\t\t\tPingDirectoly Bulk API Tool\n\n")
        ## PD API Endpoint:
        pd_api_base_url = "https://localhost:1443/directory/v1/"   # Replace with desired instance URL 
        headers = { 'Content-Type': 'application/json' }
        
        login_credentials = get_ldap_creds()
        
        while(True):
            print_menu()
            try:
                menu_selection = int(input("\nSelect Option: "))
            except (UnboundLocalError, Exception):
                pass

            if (menu_selection == 1):
                print("\n* Select input file containing entries to add.\n* Input file must be either json or raw text consisting of one entery per line enclosed in braces\n\nExample:\n{\"_dn\": \"uid=user.0,ou=people,dc=example,dc=com\",\"objectClass\": [\"top\", \"organizationalPerson\", \"inetOrgPerson\", \"pf-connected-identities\"],\"sn\": [\"Seawell\"],\"cn\": [\"Esko Seawell\"],\"givenName\": [\"Esko\"],\"uid\": [\"user.0\"],\"mail\": [\"user.0@example.com\"],\"userPassword\": [\"2FederateM0re\"],\"pf-connected-identity\": [\"auth-source=pf-local-identity:user-id=user.0\"]}\n")  
                input_file = select_input_file()
                add_ldap_entries(input_file, pd_api_base_url, headers, login_credentials)
    
            elif (menu_selection == 2):
                print("\n* Select input file containing entries to delete.\n* Input file must be either valid json with a single \"entriesToDelete\" key with a value consisting of a list of DN objects, or raw text consisting of a single DN per line\n")
                input_file = select_input_file()
                delete_ldap_entries(input_file, pd_api_base_url, headers, login_credentials)
    
            elif(menu_selection == 3):
                print("\n* Select input file containing desired modifactions for existing LDAP entires.\n* Input file mus be valid json with a single \"entriesToModify\" key with a value consisting of a list of DN objects to modify and corresponding \"modifcations\"  key for each entry\n")
                input_file = select_input_file()
                modify_ldap_entries(input_file, pd_api_base_url, headers, login_credentials)
    
            elif (menu_selection == 4):
                print("\nExiting")
                exit()
    
            elif (menu_selection not in options.keys()):
                print("Invalid option!\n")

            print("\n\n\n\n\n\t\t\tPingDirectoly Bulk API Tool")

    except KeyboardInterrupt:
        sys.exit(0)


##


def print_menu():
    print("\n\n\t\t\t* * * * Menu * * * *\n")
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
    while(True):
        try: 
            default_admin_acct = input("Log in with 'cn=Administrator'? (y/n): ")
    
            if (default_admin_acct == 'y') or (default_admin_acct == 'Y'):
                login = "cn=Administrator"
            elif (default_admin_acct == 'n') or (default_admin_acct == 'N'):
                login = input("Login: ")    
            else:
                 raise ValueError
            
            password = "2FederateM0re" #getpass("Admin Password: ")
            return (login, password)
       
        except ValueError:
            print("Invalid Entry.  Enter y/n!\n")



def add_ldap_entries(input_file, pd_api_base_url, headers, login_credentials):
    try:
        if not input_file:
                return

        # Process entries
        valid_json = validate_json(input_file)
    
        with open(input_file, 'r') as ldap_entries:
            if (valid_json):
                ldap_data = json.load(ldap_entries)
                data = ldap_data['entries']
            else: 
                data = ldap_entries

            for entry in  data: #ldap_data['entries']: #ldap_data['entries']: #in ldap_entries:
                print("\n\nAdding entry:\n\n\t{}".format(entry))
                entry = str(entry).replace('\'', '"')
                request_url="{}".format(pd_api_base_url)
                api_response = requests.post(request_url, verify=False, auth=login_credentials, headers=headers, data="{}".format(entry))

                if (api_response.status_code == 201):   
                    print("\n\tResponse Code: {} - SUCCESS\n".format(api_response.status_code))          
                else:
                    print(api_response.json())
                time.sleep(0.05)    
    except IOError:
        print("Invalid File")



def delete_ldap_entries(input_file, pd_api_base_url, headers, login_credentials):
    try:
        if not input_file:
            return

        ## Process entries
        valid_json = validate_json(input_file)
 
        with open(input_file, 'r') as ldap_entries:
            if (valid_json):
                ldap_data = json.load(ldap_entries)
                data = ldap_data['entriesToDelete']
            else: 
                data = ldap_entries

            for entry in data:
                dn = entry['dn'] if valid_json else entry.rstrip('\n')  #remove trailing newline
                print("\nDeleting entry: {}".format(dn.split(',', 1)[0]))  # strip full DN after UID
                request_url="{}{}".format(pd_api_base_url, dn)
                api_response = requests.delete(request_url, headers=headers, verify=False, auth=login_credentials)
    
                if (api_response.status_code == 204):
                    print("Response Code: {} - SUCCESS\n".format(api_response.status_code))
                else:
                    print(api_response.json())
          
            time.sleep(0.05)
    except IOError:
        print("\n\nInvalid File!\n")



def modify_ldap_entries(input_file, pd_api_base_url, headers, login_credentials):
    while(True):
        try:
            if not input_file:
                return
        
            valid_json = validate_json(input_file)

            if not valid_json:
                raise IOError
            else:
                with open(input_file, 'r') as ldap_modifications:
                    ldap_entries_to_modify = json.load(ldap_modifications)

                    for entry in ldap_entries_to_modify['entriesToModify']:
                        dn = entry['dn']
                        payload = "{{\"modifications\": \n{}}}\n".format(entry['modifications'])
                        payload = payload.replace('\'','"')
                        payload = payload.replace("True", "true")
                        payload = payload.replace("False", "false")
                        request_url = "{}{}".format(pd_api_base_url, dn)
                        print("\n\nModifying Entry: {}\n\n\t{}".format(entry['dn'], payload))
                        api_response = requests.patch(request_url, headers=headers, verify=False, auth=login_credentials, data=payload)
                        if (api_response.status_code == 200):
                            print("Response Code: {} - SUCCESS\n".format(api_response.status_code))
                        else:
                            print("Response Code: {}".format(api_response.status_code))
                        print("Response Body:\n\t{}\n".format(api_response.text))        
                break
        
        except (IOError):
            print("\n\nInvalid File!\n")
            input_file = select_input_file()
            
##


if __name__ == "__main__":
    main()